/*
 ============================================================================
 Name        : hev-tproxy-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 hev
 Description : TProxy Session
 ============================================================================
 */

#include "hev-tproxy-session.h"

void
hev_tproxy_session_run (HevTProxySession *self)
{
    HevTProxySessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_TPROXY_SESSION_TYPE);
    iface->runner (self);
}

void
hev_tproxy_session_terminate (HevTProxySession *self)
{
    HevTProxySessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_TPROXY_SESSION_TYPE);
    iface->terminator (self);
}

void
hev_tproxy_session_set_task (HevTProxySession *self, HevTask *task)
{
    HevTProxySessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_TPROXY_SESSION_TYPE);
    iface->set_task (self, task);
}

void *
hev_tproxy_session_iface (void)
{
    static char type;

    return &type;
}
