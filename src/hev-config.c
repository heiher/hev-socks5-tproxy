/*
 ============================================================================
 Name        : hev-config.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 Heiher.
 Description : Config
 ============================================================================
 */

#include <stdio.h>
#include <iniparser.h>

#include "hev-config.h"
#include "hev-config-const.h"

static char socks5_address[16];
static unsigned short socks5_port;

static char tcp_listen_address[16];
static unsigned short tcp_port;

static char dns_listen_address[16];
static unsigned short dns_port;

int
hev_config_init (const char *config_path)
{
	dictionary *ini_dict;

	ini_dict = iniparser_load (config_path);
	if (!ini_dict) {
		fprintf (stderr, "Load config from file %s failed!\n",
					config_path);
		return -1;
	}

	/* Socks5:Address */
	char *address = iniparser_getstring (ini_dict, "Socks5:Address", NULL);
	if (!address) {
		fprintf (stderr, "Get Socks5:Address from file %s failed!\n", config_path);
		iniparser_freedict (ini_dict);
		return -2;
	}
	strncpy (socks5_address, address, 16);

	/* Socks5:Port */
	socks5_port = iniparser_getint (ini_dict, "Socks5:Port", -1);
	if (-1 == socks5_port) {
		fprintf (stderr, "Get Socks5:Port from file %s failed!\n",
					config_path);
		iniparser_freedict (ini_dict);
		return -3;
	}

	/* TCP:ListenAddress */
	address = iniparser_getstring (ini_dict, "TCP:ListenAddress", NULL);
	if (address)
		strncpy (tcp_listen_address, address, 16);

	/* TCP:Port */
	tcp_port = iniparser_getint (ini_dict, "TCP:Port", -1);

	/* DNS:ListenAddress */
	address = iniparser_getstring (ini_dict, "DNS:ListenAddress", NULL);
	if (address)
		strncpy (dns_listen_address, address, 16);

	/* DNS:Port */
	dns_port = iniparser_getint (ini_dict, "DNS:Port", -1);

	if (!tcp_listen_address[0] && !dns_listen_address[0]) {
		fprintf (stderr, "Cannot found TCP or DNS in file %s!\n",
					config_path);
		iniparser_freedict (ini_dict);
		return -4;
	}

	iniparser_freedict (ini_dict);

	return 0;
}

void
hev_config_fini (void)
{
}

const char *
hev_config_get_socks5_address (void)
{
	return socks5_address;
}

unsigned short
hev_config_get_socks5_port (void)
{
	return socks5_port;
}

const char *
hev_config_get_tcp_listen_address (void)
{
	return tcp_listen_address;
}

unsigned short
hev_config_get_tcp_port (void)
{
	return tcp_port;
}

const char *
hev_config_get_dns_listen_address (void)
{
	return dns_listen_address;
}

unsigned short
hev_config_get_dns_port (void)
{
	return dns_port;
}

