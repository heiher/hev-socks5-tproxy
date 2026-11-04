/*
 ============================================================================
 Name        : hev-tsocks-cache.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2026 hev
 Description : Transparent Socket Cache
 ============================================================================
 */

#ifndef __HEV_TSOCKS_CACHE_H__
#define __HEV_TSOCKS_CACHE_H__

#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>

typedef struct _HevTSock HevTSock;

struct _HevTSock
{
    atomic_uint refs;
    atomic_uchar used;
    unsigned char transient;
    in_port_t port;
    uint32_t scope;
    uint32_t hash;
    struct in6_addr addr;
    int fd;
};

int hev_tsocks_cache_init (void);
void hev_tsocks_cache_fini (void);

HevTSock *hev_tsocks_cache_get (struct sockaddr *addr);
void hev_tsocks_cache_put (HevTSock *ts);

#endif /* __HEV_TSOCKS_CACHE_H__ */
