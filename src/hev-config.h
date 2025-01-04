/*
 ============================================================================
 Name        : hev-config.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Config
 ============================================================================
 */

#ifndef __HEV_CONFIG_H__
#define __HEV_CONFIG_H__

typedef struct _HevConfigServer HevConfigServer;

struct _HevConfigServer
{
    const char *user;
    const char *pass;
    unsigned int mark;
    short udp_in_udp;
    unsigned short port;
    unsigned char pipeline;
    char addr[256];
};

int hev_config_init (const char *path);
void hev_config_fini (void);

unsigned int hev_config_get_workers (void);

HevConfigServer *hev_config_get_socks5_server (void);
const char *hev_config_get_tcp_address (void);
const char *hev_config_get_tcp_port (void);
const char *hev_config_get_udp_address (void);
const char *hev_config_get_udp_port (void);
const char *hev_config_get_dns_upstream (void);
const char *hev_config_get_dns_address (void);
const char *hev_config_get_dns_port (void);

int hev_config_get_misc_task_stack_size (void);
int hev_config_get_misc_udp_recv_buffer_size (void);
int hev_config_get_misc_connect_timeout (void);
int hev_config_get_misc_read_write_timeout (void);
int hev_config_get_misc_limit_nofile (void);
const char *hev_config_get_misc_pid_file (void);
const char *hev_config_get_misc_log_file (void);
int hev_config_get_misc_log_level (void);

#endif /* __HEV_CONFIG_H__ */
