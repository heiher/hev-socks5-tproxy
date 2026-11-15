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

#include <netinet/in.h>

typedef struct _HevConfigServer HevConfigServer;
typedef struct _HevConfigDNS HevConfigDNS;

struct _HevConfigServer
{
    const char *user;
    const char *pass;
    unsigned int mark;
    short udp_in_udp;
    unsigned short port;
    unsigned char pipeline;
    unsigned char fastopen;
    char udp_addr[256];
    char addr[256];
};

struct _HevConfigDNS
{
    char addr[256];
    char port[8];
    struct sockaddr_in6 upstream;
};

int hev_config_init (const char *path);

unsigned int hev_config_get_workers (void);

HevConfigServer *hev_config_get_socks5_server (void);
const char *hev_config_get_tcp_address (void);
const char *hev_config_get_tcp_port (void);
const char *hev_config_get_udp_address (void);
const char *hev_config_get_udp_port (void);
int hev_config_get_dns_count (void);
HevConfigDNS *hev_config_get_dns (int index);

int hev_config_get_misc_task_stack_size (void);
int hev_config_get_misc_udp_recv_buffer_size (void);
int hev_config_get_misc_udp_copy_buffer_nums (void);
int hev_config_get_misc_connect_timeout (void);
int hev_config_get_misc_tcp_read_write_timeout (void);
int hev_config_get_misc_udp_read_write_timeout (void);
int hev_config_get_misc_limit_nofile (void);
const char *hev_config_get_misc_pid_file (void);
const char *hev_config_get_misc_log_file (void);
int hev_config_get_misc_log_level (void);

#endif /* __HEV_CONFIG_H__ */
