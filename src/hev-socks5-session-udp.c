/*
 ============================================================================
 Name        : hev-socks5-session-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
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

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-tsocks-cache.h"

#include "hev-socks5-session-udp.h"

#define task_io_yielder hev_socks5_task_io_yielder

typedef struct _HevSocks5UDPFrame HevSocks5UDPFrame;
typedef struct _HevSocks5UDPSplice HevSocks5UDPSplice;

struct _HevSocks5UDPFrame
{
    HevListNode node;
    struct sockaddr_in6 addr;
    void *data;
    size_t len;
};

struct _HevSocks5UDPSplice
{
    HevSocks5UDP *udp;
    HevTask *task;
};

static int
hev_socks5_session_udp_fwd_f (HevSocks5SessionUDP *self)
{
    HevSocks5UDPFrame *frame;
    struct sockaddr *addr;
    HevListNode *node;
    HevSocks5UDP *udp;
    int res;

    LOG_D ("%p socks5 session udp fwd f", self);

    for (;;) {
        node = hev_list_first (&self->frame_list);
        if (node)
            break;

        res = task_io_yielder (HEV_TASK_WAITIO, self);
        if (res < 0)
            return -1;
    }

    frame = container_of (node, HevSocks5UDPFrame, node);
    addr = (struct sockaddr *)&frame->addr;

    udp = HEV_SOCKS5_UDP (self);
    res = hev_socks5_udp_sendto (udp, frame->data, frame->len, addr);
    if (res <= 0) {
        LOG_E ("%p socks5 session udp fwd f send", self);
        res = -1;
    }

    hev_list_del (&self->frame_list, node);
    hev_free (frame->data);
    hev_free (frame);
    self->frames--;

    return res;
}

static int
hev_socks5_session_udp_fwd_b (HevSocks5SessionUDP *self)
{
    struct sockaddr_in6 addr = { 0 };
    struct sockaddr *saddr;
    struct sockaddr *daddr;
    HevSocks5UDP *udp;
    uint8_t buf[UDP_BUF_SIZE];
    int res;
    int fd;

    LOG_D ("%p socks5 session udp fwd b", self);

    udp = HEV_SOCKS5_UDP (self);
    fd = HEV_SOCKS5 (udp)->fd;
    if (fd < 0) {
        LOG_E ("%p socks5 session udp fd", self);
        return -1;
    }

    addr.sin6_family = AF_INET6;
    saddr = (struct sockaddr *)&addr;
    daddr = (struct sockaddr *)&self->addr;

    res = hev_socks5_udp_recvfrom (udp, buf, sizeof (buf), saddr);
    if (res <= 0) {
        LOG_E ("%p socks5 session udp fwd b recv", self);
        return -1;
    }

    fd = hev_tsocks_cache_get (saddr);
    if (fd < 0) {
        LOG_E ("%p socks5 session udp tsocks get", self);
        return -1;
    }

    res = sendto (fd, buf, res, 0, daddr, sizeof (self->addr));
    if (res <= 0) {
        if ((res < 0) && (errno == EAGAIN))
            return 0;
        LOG_E ("%p socks5 session udp fwd b send", self);
        return -1;
    }

    return 0;
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

    LOG_D ("%p socks5 session udp send", self);

    if (self->frames > UDP_POOL_SIZE)
        return -1;

    frame = hev_malloc (sizeof (HevSocks5UDPFrame));
    if (!frame)
        return -1;

    frame->len = len;
    frame->data = data;
    memset (&frame->node, 0, sizeof (frame->node));
    memcpy (&frame->addr, addr, sizeof (struct sockaddr_in6));

    self->frames++;
    hev_list_add_tail (&self->frame_list, &frame->node);
    hev_task_wakeup (self->task);

    return 0;
}

static void
splice_task_entry (void *data)
{
    HevSocks5UDPSplice *splice = data;
    HevSocks5UDP *self = splice->udp;
    HevTask *task = hev_task_self ();
    int fd;

    fd = hev_task_io_dup (hev_socks5_udp_get_fd (self));
    if (fd < 0)
        goto exit;

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        int res;

        res = hev_socks5_session_udp_fwd_b (self);
        if (res < 0)
            break;

        res = task_io_yielder (HEV_TASK_YIELD, self);
        if (res < 0)
            break;
    }

    hev_task_del_fd (task, fd);
    close (fd);

exit:
    hev_task_wakeup (splice->task);
}

static void
hev_socks5_session_udp_splice (HevSocks5Session *base)
{
    HevSocks5SessionUDP *self = HEV_SOCKS5_SESSION_UDP (base);
    HevTask *task = hev_task_self ();
    HevSocks5UDPSplice splice;
    int stack_size;

    LOG_D ("%p socks5 session udp splice", self);

    splice.task = task;
    splice.udp = self;

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    hev_task_run (task, splice_task_entry, &splice);
    task = hev_task_ref (task);

    for (;;) {
        int res;

        res = hev_socks5_session_udp_fwd_f (self);
        if (res < 0)
            break;

        res = task_io_yielder (HEV_TASK_YIELD, self);
        if (res < 0)
            break;
    }

    for (;;) {
        if (hev_task_get_state (task) == HEV_TASK_STOPPED)
            break;

        hev_task_wakeup (task);
        hev_task_yield (HEV_TASK_WAITIO);
    }

    hev_task_unref (task);
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

    HEV_SOCKS5_CLIENT_UDP_TYPE->finalizer (base);
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
        HevSocks5SessionIface *siptr;
        HevTProxySessionIface *tiptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_UDP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientUDPClass));

        okptr->name = "HevSocks5SessionUDP";
        okptr->finalizer = hev_socks5_session_udp_destruct;
        okptr->iface = hev_socks5_session_udp_iface;

        siptr = &kptr->session;
        memcpy (siptr, HEV_SOCKS5_SESSION_TYPE, sizeof (HevSocks5SessionIface));
        siptr->splicer = hev_socks5_session_udp_splice;

        tiptr = &kptr->session.base;
        tiptr->set_task = hev_socks5_session_udp_set_task;
        tiptr->terminator = hev_socks5_session_udp_terminate;
    }

    return okptr;
}
