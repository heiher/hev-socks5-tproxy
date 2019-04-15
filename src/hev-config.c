/*
 ============================================================================
 Name        : hev-config.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2019 Heiher.
 Description : Config
 ============================================================================
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <iniparser.h>

#include "hev-config.h"
#include "hev-config-const.h"

static unsigned int workers;

static struct sockaddr_in6 socks5_address;
static struct sockaddr_in6 tcp_listen_address;
static struct sockaddr_in6 dns_listen_address;

static char pid_file[1024];
static int limit_nofile;

static int
address_to_sockaddr (const char *address, unsigned short port,
                     struct sockaddr_in6 *addr)
{
    __builtin_bzero (addr, sizeof (*addr));

    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons (port);
    if (inet_pton (AF_INET, address, &addr->sin6_addr.s6_addr[12]) == 1) {
        ((uint16_t *)&addr->sin6_addr)[5] = 0xffff;
    } else {
        if (inet_pton (AF_INET6, address, &addr->sin6_addr) != 1) {
            return -1;
        }
    }

    return 0;
}

int
hev_config_init (const char *config_path)
{
    dictionary *ini_dict;

    ini_dict = iniparser_load (config_path);
    if (!ini_dict) {
        fprintf (stderr, "Load config from file %s failed!\n", config_path);
        return -1;
    }

    /* Socks5:Address */
    char *address = iniparser_getstring (ini_dict, "Socks5:Address", NULL);
    if (!address) {
        fprintf (stderr, "Get Socks5:Address from file %s failed!\n",
                 config_path);
        iniparser_freedict (ini_dict);
        return -2;
    }

    /* Socks5:Port */
    int port = iniparser_getint (ini_dict, "Socks5:Port", -1);
    if (-1 == port) {
        fprintf (stderr, "Get Socks5:Port from file %s failed!\n", config_path);
        iniparser_freedict (ini_dict);
        return -3;
    }

    if (address_to_sockaddr (address, port, &socks5_address) < 0) {
        fprintf (stderr, "Parse socks5 address failed!\n");
        iniparser_freedict (ini_dict);
        return -4;
    }

    /* TCP:ListenAddress */
    address = iniparser_getstring (ini_dict, "TCP:ListenAddress", NULL);

    /* TCP:Port */
    port = iniparser_getint (ini_dict, "TCP:Port", -1);

    address_to_sockaddr (address, port, &tcp_listen_address);

    /* DNS:ListenAddress */
    address = iniparser_getstring (ini_dict, "DNS:ListenAddress", NULL);

    /* DNS:Port */
    port = iniparser_getint (ini_dict, "DNS:Port", -1);

    address_to_sockaddr (address, port, &dns_listen_address);

    if (!tcp_listen_address.sin6_port && !dns_listen_address.sin6_port) {
        fprintf (stderr, "Cannot found TCP or DNS in file %s!\n", config_path);
        iniparser_freedict (ini_dict);
        return -5;
    }

    /* Main:Workers */
    workers = iniparser_getint (ini_dict, "Main:Workers", 1);
    if (workers <= 0)
        workers = 1;

    /* Misc:PidFile */
    char *path = iniparser_getstring (ini_dict, "Misc:PidFile", NULL);
    if (path)
        strncpy (pid_file, path, 1023);

    /* Misc:LimitNOFile */
    limit_nofile = iniparser_getint (ini_dict, "Misc:LimitNOFile", -2);

    iniparser_freedict (ini_dict);

    return 0;
}

void
hev_config_fini (void)
{
}

unsigned int
hev_config_get_workers (void)
{
    return workers;
}

struct sockaddr *
hev_config_get_socks5_address (socklen_t *addr_len)
{
    *addr_len = sizeof (socks5_address);
    return (struct sockaddr *)&socks5_address;
}

struct sockaddr *
hev_config_get_tcp_listen_address (socklen_t *addr_len)
{
    if (!tcp_listen_address.sin6_port)
        return NULL;

    *addr_len = sizeof (tcp_listen_address);
    return (struct sockaddr *)&tcp_listen_address;
}

struct sockaddr *
hev_config_get_dns_listen_address (socklen_t *addr_len)
{
    if (!dns_listen_address.sin6_port)
        return NULL;

    *addr_len = sizeof (dns_listen_address);
    return (struct sockaddr *)&dns_listen_address;
}

const char *
hev_config_get_misc_pid_file (void)
{
    if ('\0' == pid_file[0])
        return NULL;

    return pid_file;
}

int
hev_config_get_misc_limit_nofile (void)
{
    return limit_nofile;
}
