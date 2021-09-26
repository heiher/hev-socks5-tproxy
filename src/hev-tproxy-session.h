/*
 ============================================================================
 Name        : hev-tproxy-session.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 hev
 Description : TProxy Session
 ============================================================================
 */

#ifndef __HEV_TPROXY_SESSION_H__
#define __HEV_TPROXY_SESSION_H__

#include <hev-task.h>

#include "hev-object.h"

#define HEV_TPROXY_SESSION(p) ((HevTProxySession *)p)
#define HEV_TPROXY_SESSION_IFACE(p) ((HevTProxySessionIface *)p)
#define HEV_TPROXY_SESSION_TYPE (hev_tproxy_session_iface ())

typedef void HevTProxySession;
typedef struct _HevTProxySessionIface HevTProxySessionIface;

struct _HevTProxySessionIface
{
    void (*runner) (HevTProxySession *self);
    void (*terminator) (HevTProxySession *self);
    void (*set_task) (HevTProxySession *self, HevTask *task);
};

void *hev_tproxy_session_iface (void);

void hev_tproxy_session_run (HevTProxySession *self);
void hev_tproxy_session_terminate (HevTProxySession *self);

void hev_tproxy_session_set_task (HevTProxySession *self, HevTask *task);

#endif /* __HEV_TPROXY_SESSION_H__ */
