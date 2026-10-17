/*
 ============================================================================
 Name        : hev-socks5-session-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session UDP
 ============================================================================
 */

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>

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

#if defined(__linux__) && defined(UDP_SEGMENT)
static int udp_gso_max_size = -1;

static int
hev_socks5_session_udp_gso_probe (void)
{
    int size = 1024;
    int fd, res;

    /* Kernels without UDP GSO would send the coalesced datagrams as one. */
    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    res = setsockopt (fd, SOL_UDP, UDP_SEGMENT, &size, sizeof (size));
    close (fd);

    return (res == 0) ? 65535 : 0;
}

static int
hev_socks5_session_udp_sendmmsg_gso (int fd, struct mmsghdr *dmv,
                                     struct iovec *iov, int n)
{
    union
    {
        char buf[CMSG_SPACE (sizeof (uint16_t))];
        struct cmsghdr align;
    } u[n];
    struct mmsghdr mvec[n];
    unsigned int segs[n];
    int i, g, res;

    /*
     * Coalesce runs of equal sized datagrams into a single UDP GSO send, the
     * kernel splits them into separate datagrams.
     */
    for (i = 0, g = 0; i < n; g++) {
        size_t size = iov[i].iov_len;
        size_t total = size;
        int k;

        for (k = 1; (i + k) < n && k < 64 && (int)size <= udp_gso_max_size;
             k++) {
            size_t s = iov[i + k].iov_len;
            if ((s != size) || ((total + s) > 65000))
                break;
            total += s;
        }

        mvec[g] = dmv[i];
        mvec[g].msg_hdr.msg_iov = &iov[i];
        mvec[g].msg_hdr.msg_iovlen = k;
        mvec[g].msg_hdr.msg_control = NULL;
        mvec[g].msg_hdr.msg_controllen = 0;
        if (k > 1) {
            struct cmsghdr *cm;

            mvec[g].msg_hdr.msg_control = u[g].buf;
            mvec[g].msg_hdr.msg_controllen = sizeof (u[g].buf);
            cm = CMSG_FIRSTHDR (&mvec[g].msg_hdr);
            cm->cmsg_level = SOL_UDP;
            cm->cmsg_type = UDP_SEGMENT;
            cm->cmsg_len = CMSG_LEN (sizeof (uint16_t));
            *(uint16_t *)CMSG_DATA (cm) = size;
        }
        segs[g] = k;
        i += k;
    }

    res = hev_task_io_socket_sendmmsg (fd, mvec, g, MSG_WAITALL, NULL, NULL);
    if (res <= 0) {
        /* Segments larger than the path MTU are rejected, don't retry them. */
        if ((errno == EINVAL) && (segs[0] > 1)) {
            size_t size = iov[0].iov_len;
            if ((int)size <= udp_gso_max_size)
                udp_gso_max_size = size - 1;
        }
        return res;
    }

    for (i = 0, n = 0; i < res; i++)
        n += segs[i];

    return n;
}
#endif /* __linux__ && UDP_SEGMENT */

static int
hev_socks5_session_udp_sendmmsg (int fd, struct mmsghdr *dmv, struct iovec *iov,
                                 int n)
{
    int s = 0;

#if defined(__linux__) && defined(UDP_SEGMENT)
    if (udp_gso_max_size < 0)
        udp_gso_max_size = hev_socks5_session_udp_gso_probe ();

    while ((s < n) && udp_gso_max_size) {
        int r;

        r = hev_socks5_session_udp_sendmmsg_gso (fd, dmv + s, iov + s, n - s);
        if (r <= 0)
            break;

        s += r;
    }
#endif /* __linux__ && UDP_SEGMENT */

    /* Whatever GSO did not send, including the batch it refused, goes plain. */
    if (s < n) {
        int r;

        r = hev_task_io_socket_sendmmsg (fd, dmv + s, n - s, MSG_WAITALL, NULL,
                                         NULL);
        if (r <= 0)
            return s ? s : r;

        s += r;
    }

    return s;
}

static int
hev_socks5_session_udp_fwd_b (HevSocks5SessionUDP *self, unsigned int num)
{
    char buf[UDP_BUF_SIZE * num];
    HevSocks5UDPMsg smv[num];
    int i, res;
    int s = 0;

    for (i = 0; i < num; i++) {
        smv[i].buf = buf + UDP_BUF_SIZE * i;
        smv[i].len = UDP_BUF_SIZE;
    }

    res = hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (self), smv, num, 1);
    if (res <= 0) {
        if (res == -1 && errno == EAGAIN)
            return 0;
        LOG_D ("%p socks5 session udp fwd b recv", self);
        return -1;
    }

    while (s < res) {
        struct sockaddr_in6 saddr;
        struct mmsghdr dmv[res];
        struct iovec iov[res];
        int fd, f, n, r;

        for (i = s, n = 0; i < res; i++) {
            if (!smv[i].addr || smv[i].len == 0)
                break;

            if (n > 0) {
                r = hev_socks5_addr_len (smv[s].addr);
                r = memcmp (smv[s].addr, smv[i].addr, r);
                if (r)
                    break;
            }

            dmv[n].msg_hdr.msg_name = &self->addr;
            dmv[n].msg_hdr.msg_namelen = sizeof (self->addr);
            dmv[n].msg_hdr.msg_controllen = 0;
            dmv[n].msg_hdr.msg_iov = &iov[n];
            dmv[n].msg_hdr.msg_iovlen = 1;
            iov[n].iov_base = smv[i].buf;
            iov[n].iov_len = smv[i].len;
            n++;
        }

        if (n == 0) {
            /* smv[s] itself is invalid (empty payload or no address) */
            s++;
            continue;
        }

        r = hev_socks5_addr_into_sockaddr6 (smv[s].addr, &saddr, &f);
        if (r < 0) {
            LOG_D ("%p socks5 session udp fwd b addr", self);
            return -1;
        }

        fd = hev_tsocks_cache_get ((struct sockaddr *)&saddr);
        if (fd < 0) {
            LOG_D ("%p socks5 session udp tsocks get", self);
            return -1;
        }

        r = hev_socks5_session_udp_sendmmsg (fd, dmv, iov, n);
        hev_tsocks_cache_put (fd);
        if (r <= 0) {
            LOG_D ("%p socks5 session udp fwd b send", self);
            return -1;
        }

        s += n;
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
        skptr->binder = hev_socks5_session_bind;

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
