/*
 ============================================================================
 Name        : hev-main.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Main
 ============================================================================
 */

#include <stdio.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-socks5-misc.h>
#include <hev-socks5-logger.h>

#include "hev-utils.h"
#include "hev-logger.h"
#include "hev-config.h"
#include "hev-config-const.h"
#include "hev-socks5-tproxy.h"

#include "hev-main.h"

static void
show_help (const char *self_path)
{
    printf ("%s CONFIG_PATH\n", self_path);
    printf ("Version: %u.%u.%u %s\n", MAJOR_VERSION, MINOR_VERSION,
            MICRO_VERSION, COMMIT_ID);
}

int
main (int argc, char *argv[])
{
    const char *pid_file;
    const char *log_file;
    int log_level;
    int nofile;
    int res;

    if (argc != 2) {
        show_help (argv[0]);
        return -1;
    }

    res = hev_config_init (argv[1]);
    if (res < 0)
        return -2;

    log_file = hev_config_get_misc_log_file ();
    log_level = hev_config_get_misc_log_level ();

    res = hev_config_get_misc_connect_timeout ();
    hev_socks5_set_connect_timeout (res);
    res = hev_config_get_misc_read_write_timeout ();
    hev_socks5_set_tcp_timeout (res);
    res = hev_config_get_misc_read_write_timeout ();
    hev_socks5_set_udp_timeout (res);

    res = hev_logger_init (log_level, log_file);
    if (res < 0)
        return -3;

    res = hev_socks5_logger_init (log_level, log_file);
    if (res < 0)
        return -4;

    pid_file = hev_config_get_misc_pid_file ();
    if (pid_file)
        run_as_daemon (pid_file);

    res = hev_socks5_tproxy_init ();
    if (res < 0)
        return -5;

    nofile = hev_config_get_misc_limit_nofile ();
    res = set_limit_nofile (nofile);
    if (res < 0)
        LOG_W ("set limit nofile");

    hev_socks5_tproxy_run ();

    hev_socks5_tproxy_fini ();
    hev_socks5_logger_fini ();
    hev_logger_fini ();
    hev_config_fini ();

    return 0;
}

void
quit (void)
{
    hev_socks5_tproxy_stop ();
}
