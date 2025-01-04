/*
 ============================================================================
 Name        : hev-config.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Config
 ============================================================================
 */

#include <yaml.h>
#include <stdio.h>

#include "hev-logger.h"
#include "hev-config.h"

static unsigned int workers = 1;
static HevConfigServer srv;
static char tcp_address[256];
static char tcp_port[8];
static char udp_address[256];
static char udp_port[8];
static char dns_upstream[256];
static char dns_address[256];
static char dns_port[8];

static char log_file[1024];
static char pid_file[1024];
static int task_stack_size = 16384;
static int udp_recv_buffer_size = 1048576;
static int connect_timeout = 5000;
static int read_write_timeout = 60000;
static int limit_nofile = 65535;
static int log_level = HEV_LOGGER_WARN;

static int
hev_config_parse_main (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    if (!base || YAML_MAPPING_NODE != base->type)
        return -1;

    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "workers"))
            workers = strtoul (value, NULL, 10);
    }

    if (!workers)
        workers = 1;

    return 0;
}

static int
hev_config_parse_server (yaml_document_t *doc, yaml_node_t *base,
                         const char *sec, HevConfigServer *srv)
{
    yaml_node_pair_t *pair;
    static char _user[256];
    static char _pass[256];
    const char *addr = NULL;
    const char *port = NULL;
    const char *udpm = NULL;
    const char *user = NULL;
    const char *pass = NULL;
    const char *mark = NULL;
    const char *pipe = NULL;

    if (!base || YAML_MAPPING_NODE != base->type || !srv)
        return -1;

    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "port"))
            port = value;
        else if (0 == strcmp (key, "address"))
            addr = value;
        else if (0 == strcmp (key, "udp"))
            udpm = value;
        else if (0 == strcmp (key, "pipeline"))
            pipe = value;
        else if (0 == strcmp (key, "username"))
            user = value;
        else if (0 == strcmp (key, "password"))
            pass = value;
        else if (0 == strcmp (key, "mark"))
            mark = value;
    }

    if (!port) {
        fprintf (stderr, "Can't found %s.port!\n", sec);
        return -1;
    }

    if (!addr) {
        fprintf (stderr, "Can't found %s.address!\n", sec);
        return -1;
    }

    if ((user && !pass) || (!user && pass)) {
        fprintf (stderr, "Must be set both username and password %s!\n", sec);
        return -1;
    }

    strncpy (srv->addr, addr, 256 - 1);
    srv->port = strtoul (port, NULL, 10);

    if (pipe && (strcasecmp (pipe, "true") == 0))
        srv->pipeline = 1;

    if (udpm && (strcasecmp (udpm, "udp") == 0))
        srv->udp_in_udp = 1;

    if (user && pass) {
        strncpy (_user, user, 256 - 1);
        strncpy (_pass, pass, 256 - 1);
        srv->user = _user;
        srv->pass = _pass;
    }

    if (mark)
        srv->mark = strtoul (mark, NULL, 0);

    return 0;
}

static int
hev_config_parse_addr (yaml_document_t *doc, yaml_node_t *base, const char *sec,
                       char *addrbuf, char *portbuf)
{
    yaml_node_pair_t *pair;
    const char *addr = NULL;
    const char *port = NULL;

    if (!base || YAML_MAPPING_NODE != base->type)
        return -1;

    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "port"))
            port = value;
        else if (0 == strcmp (key, "address"))
            addr = value;
    }

    if (!port) {
        fprintf (stderr, "Can't found %s.port!\n", sec);
        return -1;
    }

    if (!addr) {
        fprintf (stderr, "Can't found %s.address!\n", sec);
        return -1;
    }

    strncpy (addrbuf, addr, 256 - 1);
    strncpy (portbuf, port, 8 - 1);
    return 0;
}

static int
hev_config_parse_dns_addr (yaml_document_t *doc, yaml_node_t *base,
                           const char *sec)
{
    yaml_node_pair_t *pair;
    const char *addr = NULL;
    const char *port = NULL;
    const char *upstream = NULL;

    if (!base || YAML_MAPPING_NODE != base->type)
        return -1;

    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "port"))
            port = value;
        else if (0 == strcmp (key, "address"))
            addr = value;
        else if (0 == strcmp (key, "upstream"))
            upstream = value;
    }

    if (!port) {
        fprintf (stderr, "Can't found %s.port!\n", sec);
        return -1;
    }

    if (!addr) {
        fprintf (stderr, "Can't found %s.address!\n", sec);
        return -1;
    }

    if (!upstream) {
        fprintf (stderr, "Can't found %s.upstream!\n", sec);
        return -1;
    }

    strncpy (dns_upstream, upstream, 256 - 1);
    strncpy (dns_address, addr, 256 - 1);
    strncpy (dns_port, port, 8 - 1);
    return 0;
}

static int
hev_config_parse_log_level (const char *value)
{
    if (0 == strcmp (value, "debug"))
        return HEV_LOGGER_DEBUG;
    else if (0 == strcmp (value, "info"))
        return HEV_LOGGER_INFO;
    else if (0 == strcmp (value, "error"))
        return HEV_LOGGER_ERROR;

    return HEV_LOGGER_WARN;
}

static int
hev_config_parse_misc (yaml_document_t *doc, yaml_node_t *base)
{
    yaml_node_pair_t *pair;

    if (!base || YAML_MAPPING_NODE != base->type)
        return -1;

    for (pair = base->data.mapping.pairs.start;
         pair < base->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key, *value;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        key = (const char *)node->data.scalar.value;

        node = yaml_document_get_node (doc, pair->value);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;
        value = (const char *)node->data.scalar.value;

        if (0 == strcmp (key, "task-stack-size"))
            task_stack_size = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "udp-recv-buffer-size"))
            udp_recv_buffer_size = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "connect-timeout"))
            connect_timeout = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "read-write-timeout"))
            read_write_timeout = strtoul (value, NULL, 10);
        else if (0 == strcmp (key, "pid-file"))
            strncpy (pid_file, value, 1024 - 1);
        else if (0 == strcmp (key, "log-file"))
            strncpy (log_file, value, 1024 - 1);
        else if (0 == strcmp (key, "log-level"))
            log_level = hev_config_parse_log_level (value);
        else if (0 == strcmp (key, "limit-nofile"))
            limit_nofile = strtol (value, NULL, 10);
    }

    return 0;
}

static int
hev_config_parse_doc (yaml_document_t *doc)
{
    yaml_node_t *root;
    yaml_node_pair_t *pair;

    root = yaml_document_get_root_node (doc);
    if (!root || YAML_MAPPING_NODE != root->type)
        return -1;

    for (pair = root->data.mapping.pairs.start;
         pair < root->data.mapping.pairs.top; pair++) {
        yaml_node_t *node;
        const char *key;
        int res = 0;

        if (!pair->key || !pair->value)
            break;

        node = yaml_document_get_node (doc, pair->key);
        if (!node || YAML_SCALAR_NODE != node->type)
            break;

        key = (const char *)node->data.scalar.value;
        node = yaml_document_get_node (doc, pair->value);

        if (0 == strcmp (key, "main"))
            res = hev_config_parse_main (doc, node);
        else if (0 == strcmp (key, "socks5"))
            res = hev_config_parse_server (doc, node, key, &srv);
        else if (0 == strcmp (key, "tcp"))
            res = hev_config_parse_addr (doc, node, key, tcp_address, tcp_port);
        else if (0 == strcmp (key, "udp"))
            res = hev_config_parse_addr (doc, node, key, udp_address, udp_port);
        else if (0 == strcmp (key, "dns"))
            res = hev_config_parse_dns_addr (doc, node, key);
        else if (0 == strcmp (key, "misc"))
            res = hev_config_parse_misc (doc, node);

        if (res < 0)
            return -1;
    }

    return 0;
}

int
hev_config_init (const char *config_path)
{
    yaml_parser_t parser;
    yaml_document_t doc;
    FILE *fp;
    int res = -1;

    if (!yaml_parser_initialize (&parser))
        goto exit;

    fp = fopen (config_path, "r");
    if (!fp) {
        fprintf (stderr, "Open %s failed!\n", config_path);
        goto free_parser;
    }

    yaml_parser_set_input_file (&parser, fp);
    if (!yaml_parser_load (&parser, &doc)) {
        fprintf (stderr, "Parse %s failed!\n", config_path);
        goto close_fp;
    }

    res = hev_config_parse_doc (&doc);
    yaml_document_delete (&doc);

close_fp:
    fclose (fp);
free_parser:
    yaml_parser_delete (&parser);
exit:
    return res;
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

HevConfigServer *
hev_config_get_socks5_server (void)
{
    return &srv;
}

const char *
hev_config_get_tcp_address (void)
{
    if ('\0' == tcp_address[0])
        return NULL;

    return tcp_address;
}

const char *
hev_config_get_tcp_port (void)
{
    return tcp_port;
}

const char *
hev_config_get_udp_address (void)
{
    if ('\0' == udp_address[0])
        return NULL;

    return udp_address;
}

const char *
hev_config_get_udp_port (void)
{
    return udp_port;
}

const char *
hev_config_get_dns_upstream (void)
{
    return dns_upstream;
}

const char *
hev_config_get_dns_address (void)
{
    if ('\0' == dns_address[0])
        return NULL;

    return dns_address;
}

const char *
hev_config_get_dns_port (void)
{
    return dns_port;
}

int
hev_config_get_misc_task_stack_size (void)
{
    return task_stack_size;
}

int
hev_config_get_misc_udp_recv_buffer_size (void)
{
    return udp_recv_buffer_size;
}

int
hev_config_get_misc_connect_timeout (void)
{
    return connect_timeout;
}

int
hev_config_get_misc_read_write_timeout (void)
{
    return read_write_timeout;
}

int
hev_config_get_misc_limit_nofile (void)
{
    return limit_nofile;
}

const char *
hev_config_get_misc_pid_file (void)
{
    if ('\0' == pid_file[0])
        return NULL;

    return pid_file;
}

const char *
hev_config_get_misc_log_file (void)
{
    if ('\0' == log_file[0])
        return "stderr";

    return log_file;
}

int
hev_config_get_misc_log_level (void)
{
    return log_level;
}
