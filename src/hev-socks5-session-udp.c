/*
 ============================================================================
 Name        : hev-socks5-session-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session UDP
 ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-udp.h>
#include <hev-socks5-misc.h>
#include <hev-socks5-client-udp.h>

#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-config.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-tsocks-cache.h"

#include "hev-socks5-session-udp.h"

typedef struct _HevSocks5UDPFrame HevSocks5UDPFrame;

struct _HevSocks5UDPFrame
{
    HevListNode node;
    HevSocks5Addr addr;
    void *data;
    size_t len;
};

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5 *self = data;

    if (self->type == HEV_SOCKS5_TYPE_UDP_IN_UDP) {
        ssize_t res;
        char buf;

        res = recv (self->fd, &buf, sizeof (buf), 0);
        if ((res == 0) || ((res < 0) && (errno != EAGAIN))) {
            hev_socks5_set_timeout (self, 0);
            return -1;
        }
    }

    return hev_socks5_task_io_yielder (type, data);
}

static int
hev_socks5_session_udp_fwd_f (HevSocks5SessionUDP *self, unsigned int num)
{
    HevSocks5UDPMsg msgv[num];
    HevSocks5UDPFrame *frame;
    HevListNode *node;
    int i, res;

    res = self->frames;
    if (res <= 0)
        return 0;

    res = (res > num) ? num : res;
    node = hev_list_first (&self->frame_list);
    for (i = 0; i < res; i++) {
        frame = container_of (node, HevSocks5UDPFrame, node);
        node = hev_list_node_next (node);

        msgv[i].buf = frame->data;
        msgv[i].len = frame->len;
        msgv[i].addr = &frame->addr;
    }

    res = hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (self), msgv, res);
    if (res <= 0) {
        LOG_D ("%p socks5 session udp fwd f send", self);
        return -1;
    }

    for (i = 0; i < res; i++) {
        node = hev_list_first (&self->frame_list);
        frame = container_of (node, HevSocks5UDPFrame, node);

        hev_list_del (&self->frame_list, node);
        hev_free (frame->data);
        hev_free (frame);
        self->frames--;
    }

    return 1;
}

static int
hev_socks5_session_udp_fwd_b (HevSocks5SessionUDP *self, unsigned int num)
{
    char buf[UDP_BUF_SIZE * num];
    HevSocks5UDPMsg msgv[num];
    int i, res;

    for (i = 0; i < num; i++) {
        msgv[i].buf = buf + UDP_BUF_SIZE * i;
        msgv[i].len = UDP_BUF_SIZE;
    }

    res = hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (self), msgv, num, 1);
    if (res <= 0) {
        if (res == -1 && errno == EAGAIN)
            return 0;
        LOG_D ("%p socks5 session udp fwd b recv", self);
        return -1;
    }

    for (i = 0; i < res; i++) {
        struct sockaddr_in6 saddr;
        int ret, fd, family;

        ret = hev_socks5_addr_into_sockaddr6 (msgv[i].addr, &saddr, &family);
        if (ret < 0) {
            LOG_D ("%p socks5 session udp fwd b addr", self);
            return -1;
        }

        fd = hev_tsocks_cache_get ((struct sockaddr *)&saddr);
        if (fd < 0) {
            LOG_D ("%p socks5 session udp tsocks get", self);
            return -1;
        }

        ret = sendto (fd, msgv[i].buf, msgv[i].len, 0,
                      (struct sockaddr *)&self->addr, sizeof (self->addr));
        hev_tsocks_cache_put (fd);
        if (ret <= 0) {
            LOG_D ("%p socks5 session udp fwd b send", self);
            return -1;
        }
    }

    return 1;
}

HevSocks5SessionUDP *
hev_socks5_session_udp_new (struct sockaddr *addr)
{
    HevSocks5SessionUDP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionUDP));
    if (!self)
        return NULL;

    res = hev_socks5_session_udp_construct (self, addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 session udp new", self);

    return self;
}

int
hev_socks5_session_udp_send (HevSocks5SessionUDP *self, void *data, size_t len,
                             struct sockaddr *addr)
{
    HevSocks5UDPFrame *frame;

    if (self->frames > UDP_POOL_SIZE)
        return -1;

    frame = hev_malloc (sizeof (HevSocks5UDPFrame));
    if (!frame)
        return -1;

    frame->len = len;
    frame->data = data;
    memset (&frame->node, 0, sizeof (frame->node));
    hev_socks5_addr_from_sockaddr6 (&frame->addr, (struct sockaddr_in6 *)addr);

    self->frames++;
    hev_list_add_tail (&self->frame_list, &frame->node);
    hev_task_wakeup (self->task);

    return 0;
}

static uint16_t
hev_socks5_addr_get_port (const HevSocks5Addr *addr)
{
    uint16_t port = 0;

    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        port = addr->ipv4.port;
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        port = addr->ipv6.port;
        break;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        memcpy (&port, addr->domain.addr + addr->domain.len, 2);
    }

    return port;
}

static int
hev_socks5_session_udp_set_upstream_addr (HevSocks5Client *base,
                                          HevSocks5Addr *addr)
{
    HevConfigServer *srv = hev_config_get_socks5_server ();
    HevSocks5ClientClass *ckptr;

    if (srv->udp_in_udp && srv->udp_addr[0]) {
        uint16_t port = hev_socks5_addr_get_port (addr);
        hev_socks5_addr_from_name (addr, srv->udp_addr, port);
    }

    ckptr = HEV_SOCKS5_CLIENT_CLASS (HEV_SOCKS5_CLIENT_UDP_TYPE);
    return ckptr->set_upstream_addr (base, addr);
}

static int
hev_socks5_session_udp_bind (HevSocks5 *self, int fd,
                             const struct sockaddr *dest)
{
    HevConfigServer *srv;

    LOG_D ("%p socks5 session udp bind", self);

    srv = hev_config_get_socks5_server ();

    if (srv->mark) {
        int res;

        res = set_sock_mark (fd, srv->mark);
        if (res < 0)
            return -1;
    }

    return 0;
}

static void
hev_socks5_session_udp_splice (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);
    HevTask *task = hev_task_self ();
    int res_f = 1, res_b = 1;
    int num;
    int fd;

    LOG_D ("%p socks5 session udp splice", self);

    num = hev_config_get_misc_udp_copy_buffer_nums ();
    fd = hev_socks5_udp_get_fd (HEV_SOCKS5_UDP (self));
    if (hev_task_mod_fd (task, fd, POLLIN | POLLOUT) < 0)
        hev_task_add_fd (task, fd, POLLIN | POLLOUT);

    for (;;) {
        HevTaskYieldType type;

        if (res_f >= 0)
            res_f = hev_socks5_session_udp_fwd_f (self, num);
        if (res_b >= 0)
            res_b = hev_socks5_session_udp_fwd_b (self, num);

        if (res_f > 0 || res_b > 0)
            type = HEV_TASK_YIELD;
        else if ((res_f & res_b) == 0)
            type = HEV_TASK_WAITIO;
        else
            break;

        if (task_io_yielder (type, self))
            break;
    }
}

static void
hev_socks5_session_udp_terminate (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);

    LOG_D ("%p socks5 session udp terminate", self);

    hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
    hev_task_wakeup (self->task);
}

static void
hev_socks5_session_udp_set_task (HevSocks5Session *base, HevTask *task)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);

    self->task = task;
}

int
hev_socks5_session_udp_construct (HevSocks5SessionUDP *self,
                                  struct sockaddr *addr)
{
    HevConfigServer *srv = hev_config_get_socks5_server ();
    int type;
    int res;

    if (srv->udp_in_udp)
        type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
    else
        type = HEV_SOCKS5_TYPE_UDP_IN_TCP;

    res = hev_socks5_client_udp_construct (&self->base, type);
    if (res < 0)
        return -1;

    LOG_D ("%p socks5 session udp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SESSION_UDP_TYPE;

    memcpy (&self->addr, addr, sizeof (struct sockaddr_in6));

    return 0;
}

void
hev_socks5_session_udp_destruct (HevObject *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);
    HevListNode *node;

    LOG_D ("%p socks5 session udp destruct", self);

    node = hev_list_first (&self->frame_list);
    while (node) {
        HevSocks5UDPFrame *frame;

        frame = container_of (node, HevSocks5UDPFrame, node);
        node = hev_list_node_next (node);
        hev_free (frame->data);
        hev_free (frame);
    }

    HEV_SOCKS5_CLIENT_UDP_TYPE->destruct (base);
}

static void *
hev_socks5_session_udp_iface (HevObject *base, void *type)
{
    if (type == HEV_TPROXY_SESSION_TYPE || type == HEV_SOCKS5_SESSION_TYPE) {
        HevSocks5SessionUDPClass *klass = HEV_OBJECT_GET_CLASS (base);
        return &klass->session;
    }

    return HEV_SOCKS5_CLIENT_UDP_TYPE->iface (base, type);
}

HevObjectClass *
hev_socks5_session_udp_class (void)
{
    static HevSocks5SessionUDPClass klass;
    HevSocks5SessionUDPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5Class *skptr;
        HevSocks5ClientClass *ckptr;
        HevSocks5SessionIface *siptr;
        HevTProxySessionIface *tiptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_UDP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientUDPClass));

        okptr->name = "HevSocks5SessionUDP";
        okptr->destruct = hev_socks5_session_udp_destruct;
        okptr->iface = hev_socks5_session_udp_iface;

        skptr = HEV_SOCKS5_CLASS (kptr);
        skptr->binder = hev_socks5_session_udp_bind;

        ckptr = HEV_SOCKS5_CLIENT_CLASS (kptr);
        ckptr->set_upstream_addr = hev_socks5_session_udp_set_upstream_addr;

        siptr = &kptr->session;
        memcpy (siptr, HEV_SOCKS5_SESSION_TYPE, sizeof (HevSocks5SessionIface));
        siptr->splicer = hev_socks5_session_udp_splice;

        tiptr = &kptr->session.base;
        tiptr->set_task = hev_socks5_session_udp_set_task;
        tiptr->terminator = hev_socks5_session_udp_terminate;
    }

    return okptr;
}
