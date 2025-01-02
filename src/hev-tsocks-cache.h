/*
 ============================================================================
 Name        : hev-tsocks-cache.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Transparent Socket Cache
 ============================================================================
 */

#ifndef __HEV_TSOCKS_CACHE_H__
#define __HEV_TSOCKS_CACHE_H__

#include <netinet/in.h>

int hev_tsocks_cache_init (void);
void hev_tsocks_cache_fini (void);

int hev_tsocks_cache_get (struct sockaddr *addr);
void hev_tsocks_cache_put (int fd);

#endif /* __HEV_TSOCKS_CACHE_H__ */
