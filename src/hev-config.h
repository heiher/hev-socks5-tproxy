/*
 ============================================================================
 Name        : hev-config.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Config
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

int hev_config_init (const char *path);
void hev_config_fini (void);

const char *hev_config_get_socks5_address (int *port);
const char *hev_config_get_tcp_address (void);
const char *hev_config_get_tcp_port (void);
const char *hev_config_get_udp_address (void);
const char *hev_config_get_udp_port (void);

int hev_config_get_misc_limit_nofile (void);
const char *hev_config_get_misc_pid_file (void);
const char *hev_config_get_misc_log_file (void);
int hev_config_get_misc_log_level (void);

#endif /* __HEV_CONFIG_H__ */
