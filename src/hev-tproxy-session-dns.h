/*
 ============================================================================
 Name        : hev-tproxy-session-dns.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 hev
 Description : TProxy Session DNS
 ============================================================================
 */

#ifndef __HEV_TPROXY_SESSION_DNS_H__
#define __HEV_TPROXY_SESSION_DNS_H__

#include <netinet/in.h>

#include "hev-list.h"
#include "hev-object.h"
#include "hev-tproxy-session.h"

#define HEV_TPROXY_SESSION_DNS(p) ((HevTProxySessionDNS *)p)
#define HEV_TPROXY_SESSION_DNS_CLASS(p) ((HevTProxySessionDNSClass *)p)
#define HEV_TPROXY_SESSION_DNS_TYPE (hev_tproxy_session_dns_class ())

typedef struct _HevTProxySessionDNS HevTProxySessionDNS;
typedef struct _HevTProxySessionDNSClass HevTProxySessionDNSClass;

struct _HevTProxySessionDNS
{
    HevObject base;

    HevTask *task;
    HevListNode node;
    unsigned int size;
    unsigned int timeout;
    struct sockaddr_in6 saddr;
    struct sockaddr_in6 daddr;
    unsigned char buffer[0];
};

struct _HevTProxySessionDNSClass
{
    HevObjectClass base;

    HevTProxySessionIface session;
};

HevObjectClass *hev_tproxy_session_dns_class (void);

int hev_tproxy_session_dns_construct (HevTProxySessionDNS *self);

HevTProxySessionDNS *hev_tproxy_session_dns_new (void);

struct sockaddr *hev_tproxy_session_dns_get_saddr (HevTProxySessionDNS *self);
struct sockaddr *hev_tproxy_session_dns_get_daddr (HevTProxySessionDNS *self);

void *hev_tproxy_session_dns_get_buffer (HevTProxySessionDNS *self);
void hev_tproxy_session_dns_set_size (HevTProxySessionDNS *self, unsigned size);

#endif /* __HEV_TPROXY_SESSION_DNS_H__ */
