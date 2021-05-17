/*
 ============================================================================
 Name        : hev-socks5-session-tcp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Socks5 Session TCP
 ============================================================================
 */

#include <unistd.h>

#include <hev-socks5-tcp.h>
#include <hev-socks5-client-tcp.h>
#include <hev-memory-allocator.h>

#include "hev-logger.h"

#include "hev-socks5-session-tcp.h"

static void
hev_socks5_session_tcp_splice (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp splice", self);

    hev_socks5_tcp_splice (HEV_SOCKS5_TCP (base->client), self->fd);
}

static HevSocks5SessionTCPClass _klass = {
    {
        .name = "HevSoscks5SessionTCP",
        .splicer = hev_socks5_session_tcp_splice,
        .finalizer = hev_socks5_session_tcp_destruct,
    },
};

int
hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self)
{
    int res;

    res = hev_socks5_session_construct (&self->base);
    if (res < 0)
        return -1;

    LOG_D ("%p socks5 session tcp construct", self);

    HEV_SOCKS5_SESSION (self)->klass = HEV_SOCKS5_SESSION_CLASS (&_klass);

    return 0;
}

void
hev_socks5_session_tcp_destruct (HevSocks5Session *base)
{
    HevSocks5SessionTCP *self = HEV_SOCKS5_SESSION_TCP (base);

    LOG_D ("%p socks5 session tcp destruct", self);

    if (self->fd >= 0)
        close (self->fd);

    hev_socks5_session_destruct (base);
}

HevSocks5SessionTCP *
hev_socks5_session_tcp_new (struct sockaddr *addr, int fd)
{
    HevSocks5SessionTCP *self;
    HevSocks5ClientTCP *tcp;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5SessionTCP));
    if (!self)
        return NULL;

    LOG_D ("%p socks5 session tcp new", self);

    res = hev_socks5_session_tcp_construct (self);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    tcp = hev_socks5_client_tcp_new_ip (addr);
    if (!tcp) {
        hev_free (self);
        return NULL;
    }

    self->fd = fd;
    self->base.client = HEV_SOCKS5_CLIENT (tcp);

    return self;
}
