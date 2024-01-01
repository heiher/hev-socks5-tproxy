/*
 ============================================================================
 Name        : hev-socks5-session-tcp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 Session TCP
 ============================================================================
 */

#include <string.h>
#include <unistd.h>

#include <hev-socks5-tcp.h>
#include <hev-socks5-client-tcp.h>
#include <hev-memory-allocator.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"

#include "hev-socks5-session-tcp.h"

HevSocks5SessionTCP *
hev_socks5_session_tcp_new (struct sockaddr *addr, int fd)
{
    HevSocks5SessionTCP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionTCP));
    if (!self)
        return NULL;

    res = hev_socks5_session_tcp_construct (self, addr, fd);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 session tcp new", self);

    return self;
}

static int
hev_socks5_session_tcp_bind (HevSocks5 *self, int fd,
                             const struct sockaddr *dest)
{
    HevConfigServer *srv;

    LOG_D ("%p socks5 session tcp bind", self);

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
hev_socks5_session_tcp_splice (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp splice", self);

    hev_socks5_tcp_splice (HEV_SOCKS5_TCP (self), self->fd);
}

static void
hev_socks5_session_tcp_terminate (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp terminate", self);

    hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
    hev_task_wakeup (self->task);
}

static void
hev_socks5_session_tcp_set_task (HevSocks5Session *base, HevTask *task)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    self->task = task;
}

int
hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self,
                                  struct sockaddr *addr, int fd)
{
    int res;

    res = hev_socks5_client_tcp_construct_ip (&self->base, addr);
    if (res < 0)
        return -1;

    LOG_D ("%p socks5 session tcp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SESSION_TCP_TYPE;

    self->fd = fd;

    return 0;
}

static void
hev_socks5_session_tcp_destruct (HevObject *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp destruct", self);

    if (self->fd >= 0)
        close (self->fd);

    HEV_SOCKS5_CLIENT_TCP_TYPE->finalizer (base);
}

static void *
hev_socks5_session_tcp_iface (HevObject *base, void *type)
{
    if (type == HEV_TPROXY_SESSION_TYPE || type == HEV_SOCKS5_SESSION_TYPE) {
        HevSocks5SessionTCPClass *klass = HEV_OBJECT_GET_CLASS (base);
        return &klass->session;
    }

    return HEV_SOCKS5_CLIENT_TCP_TYPE->iface (base, type);
}

HevObjectClass *
hev_socks5_session_tcp_class (void)
{
    static HevSocks5SessionTCPClass klass;
    HevSocks5SessionTCPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5Class *skptr;
        HevSocks5SessionIface *siptr;
        HevTProxySessionIface *tiptr;
        void *ptr;

        ptr = HEV_SOCKS5_CLIENT_TCP_TYPE;
        memcpy (kptr, ptr, sizeof (HevSocks5ClientTCPClass));

        okptr->name = "HevSocks5SessionTCP";
        okptr->finalizer = hev_socks5_session_tcp_destruct;
        okptr->iface = hev_socks5_session_tcp_iface;

        skptr = HEV_SOCKS5_CLASS (kptr);
        skptr->binder = hev_socks5_session_tcp_bind;

        siptr = &kptr->session;
        memcpy (siptr, HEV_SOCKS5_SESSION_TYPE, sizeof (HevSocks5SessionIface));
        siptr->splicer = hev_socks5_session_tcp_splice;

        tiptr = &kptr->session.base;
        tiptr->set_task = hev_socks5_session_tcp_set_task;
        tiptr->terminator = hev_socks5_session_tcp_terminate;
    }

    return okptr;
}
