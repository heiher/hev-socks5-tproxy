/*
 ============================================================================
 Name        : hev-tproxy-session-dns.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2024 hev
 Description : TProxy Session DNS
 ============================================================================
 */

#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-config.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-tsocks-cache.h"

#include "hev-tproxy-session-dns.h"

static int
io_yielder (HevTaskYieldType type, void *data)
{
    HevTProxySessionDNS *self = data;

    if (type == HEV_TASK_YIELD) {
        hev_task_yield (HEV_TASK_YIELD);
        return 0;
    }

    if (hev_task_sleep (self->timeout) == 0)
        return -1;

    return 0;
}

struct sockaddr *
hev_tproxy_session_dns_get_saddr (HevTProxySessionDNS *self)
{
    return (struct sockaddr *)&self->saddr;
}

struct sockaddr *
hev_tproxy_session_dns_get_daddr (HevTProxySessionDNS *self)
{
    return (struct sockaddr *)&self->daddr;
}

void *
hev_tproxy_session_dns_get_buffer (HevTProxySessionDNS *self)
{
    return self->buffer;
}

void
hev_tproxy_session_dns_set_size (HevTProxySessionDNS *self, unsigned size)
{
    self->size = size;
}

HevTProxySessionDNS *
hev_tproxy_session_dns_new (void)
{
    HevTProxySessionDNS *self;
    int res;

    self = hev_malloc (sizeof (HevTProxySessionDNS) + UDP_BUF_SIZE);
    if (!self)
        return NULL;

    memset (self, 0, sizeof (HevTProxySessionDNS));

    res = hev_tproxy_session_dns_construct (self);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("tproxy session dns new");

    return self;
}

static int
hev_tproxy_session_dns_parse_ipv4 (const char *addr, struct sockaddr_in6 *saddr)
{
    int res;

    res = inet_pton (AF_INET, addr, &saddr->sin6_addr.s6_addr[12]);
    if (res == 0)
        return -1;

    saddr->sin6_addr.s6_addr[10] = 0xff;
    saddr->sin6_addr.s6_addr[11] = 0xff;

    return 0;
}

static int
hev_tproxy_session_dns_parse_ipv6 (const char *addr, struct sockaddr_in6 *saddr)
{
    int res;

    res = inet_pton (AF_INET6, addr, &saddr->sin6_addr);
    if (res == 0)
        return -1;

    return 0;
}

static int
hev_tproxy_session_dns_parse_ip (const char *addr, int port,
                                 struct sockaddr_in6 *saddr)
{
    int res;

    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = htons (port);

    res = hev_tproxy_session_dns_parse_ipv4 (addr, saddr);
    if (res == 0)
        return 0;

    res = hev_tproxy_session_dns_parse_ipv6 (addr, saddr);
    if (res == 0)
        return 0;

    return -1;
}

static int
hev_tproxy_session_dns_bind (HevTProxySessionDNS *self, int fd)
{
    HevConfigServer *srv;

    LOG_D ("%p tproxy session dns bind", self);

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
hev_tproxy_session_dns_run (HevTProxySession *base)
{
    HevTProxySessionDNS *self = HEV_TPROXY_SESSION_DNS (base);
    static struct sockaddr_in6 addr;
    struct sockaddr *sap;
    struct sockaddr *dap;
    int res;
    int tfd;
    int fd;

    LOG_D ("tproxy session dns run");

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    hev_task_add_fd (hev_task_self (), fd, POLLIN | POLLOUT);

    if (addr.sin6_family == 0) {
        const char *upstream;

        upstream = hev_config_get_dns_upstream ();
        hev_tproxy_session_dns_parse_ip (upstream, 53, &addr);
    }

    res = hev_tproxy_session_dns_bind (self, fd);
    if (res < 0)
        goto exit;

    res = hev_task_io_socket_sendto (fd, self->buffer, self->size, 0,
                                     (struct sockaddr *)&addr, sizeof (addr),
                                     io_yielder, self);
    if (res <= 0)
        goto exit;

    res = hev_task_io_socket_recvfrom (fd, self->buffer, UDP_BUF_SIZE, 0, NULL,
                                       NULL, io_yielder, self);
    if (res <= 0)
        goto exit;

    sap = (struct sockaddr *)&self->saddr;
    dap = (struct sockaddr *)&self->daddr;

    tfd = hev_tsocks_cache_get (dap);
    if (tfd < 0)
        goto exit;

    sendto (tfd, self->buffer, res, 0, sap, sizeof (self->saddr));
    hev_tsocks_cache_put (tfd);

exit:
    close (fd);
}

static void
hev_tproxy_session_dns_terminate (HevTProxySession *base)
{
    HevTProxySessionDNS *self = HEV_TPROXY_SESSION_DNS (base);

    LOG_D ("tproxy session dns terminate");

    self->timeout = 0;
    hev_task_wakeup (self->task);
}

static void
hev_tproxy_session_dns_set_task (HevTProxySession *base, HevTask *task)
{
    HevTProxySessionDNS *self = HEV_TPROXY_SESSION_DNS (base);

    self->task = task;
}

int
hev_tproxy_session_dns_construct (HevTProxySessionDNS *self)
{
    int res;

    res = hev_object_construct (&self->base);
    if (res < 0)
        return -1;

    LOG_D ("tproxy session dns construct");

    HEV_OBJECT (self)->klass = HEV_TPROXY_SESSION_DNS_TYPE;

    self->timeout = 10000;

    return 0;
}

void
hev_tproxy_session_dns_destruct (HevObject *base)
{
    LOG_D ("tproxy session dns destruct");

    HEV_OBJECT_TYPE->destruct (base);
    hev_free (base);
}

static void *
hev_tproxy_session_dns_iface (HevObject *base, void *type)
{
    HevTProxySessionDNSClass *klass = HEV_OBJECT_GET_CLASS (base);

    return &klass->session;
}

HevObjectClass *
hev_tproxy_session_dns_class (void)
{
    static HevTProxySessionDNSClass klass;
    HevTProxySessionDNSClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevTProxySessionIface *tiptr;

        memcpy (kptr, HEV_OBJECT_TYPE, sizeof (HevObjectClass));

        okptr->name = "HevTProxySessionDNS";
        okptr->destruct = hev_tproxy_session_dns_destruct;
        okptr->iface = hev_tproxy_session_dns_iface;

        tiptr = &kptr->session;
        memcpy (tiptr, HEV_TPROXY_SESSION_TYPE, sizeof (HevTProxySessionIface));
        tiptr->runner = hev_tproxy_session_dns_run;
        tiptr->terminator = hev_tproxy_session_dns_terminate;
        tiptr->set_task = hev_tproxy_session_dns_set_task;
    }

    return okptr;
}
