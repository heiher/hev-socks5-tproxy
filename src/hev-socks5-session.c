/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Socks5 Session
 ============================================================================
 */

#include <string.h>

#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-config.h"
#include "hev-socks5-client.h"

#include "hev-socks5-session.h"

static void
hev_socks5_session_run (HevTProxySession *base)
{
    HevSocks5SessionIface *iface;
    HevConfigServer *srv;
    int res;

    LOG_D ("%p socks5 session run", base);

    srv = hev_config_get_socks5_server ();

    res = hev_socks5_client_connect (HEV_SOCKS5_CLIENT (base), srv->addr,
                                     srv->port);
    if (res < 0) {
        LOG_I ("%p socks5 session connect", base);
        return;
    }

    if (srv->user && srv->pass) {
        hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (base), srv->user,
                                    srv->pass);
        LOG_D ("%p socks5 client auth %s:%s", base, srv->user, srv->pass);
    }

    res = hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (base), srv->pipeline);
    if (res < 0) {
        LOG_I ("%p socks5 session handshake", base);
        return;
    }

    iface = HEV_OBJECT_GET_IFACE (base, HEV_SOCKS5_SESSION_TYPE);
    iface->splicer (HEV_SOCKS5_SESSION (base));
}

int
hev_socks5_session_bind (HevSocks5 *self, int fd, const struct sockaddr *dest)
{
    HevConfigServer *srv;
    unsigned int mark;

    LOG_D ("%p socks5 session bind", self);

    srv = hev_config_get_socks5_server ();
    mark = srv->mark;

    if (mark) {
        int res;

        res = set_sock_mark (fd, mark);
        if (res < 0)
            return -1;
    }

    set_sock_tcp_fastopen (fd, srv->fastopen);

    return 0;
}

void *
hev_socks5_session_iface (void)
{
    static HevSocks5SessionIface type = {
        {
            .runner = hev_socks5_session_run,
        },
    };

    return &type;
}
