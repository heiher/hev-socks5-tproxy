/*
 ============================================================================
 Name        : hev-socks5-tproxy.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Socks5 TProxy
 ============================================================================
 */

#ifndef __HEV_SOCKS5_TPROXY_H__
#define __HEV_SOCKS5_TPROXY_H__

int hev_socks5_tproxy_init (void);
void hev_socks5_tproxy_fini (void);

void hev_socks5_tproxy_run (void);
void hev_socks5_tproxy_stop (void);

#endif /* __HEV_SOCKS5_TPROXY_H__ */
