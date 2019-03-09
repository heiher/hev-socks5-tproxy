/*
 ============================================================================
 Name        : hev-config.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2019 Heiher.
 Description : Config
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

int hev_config_init (const char *config_path);
void hev_config_fini (void);

unsigned int hev_config_get_workers (void);

const char *hev_config_get_socks5_address (void);
unsigned short hev_config_get_socks5_port (void);

const char *hev_config_get_tcp_listen_address (void);
unsigned short hev_config_get_tcp_port (void);

const char *hev_config_get_dns_listen_address (void);
unsigned short hev_config_get_dns_port (void);

const char *hev_config_get_misc_pid_file (void);

int hev_config_get_misc_limit_nofile (void);

#endif /* __HEV_CONFIG_H__ */
