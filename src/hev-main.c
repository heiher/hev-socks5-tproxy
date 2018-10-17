/*
 ============================================================================
 Name        : hev-main.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description : Main
 ============================================================================
 */

#include <stdio.h>

#include "hev-main.h"
#include "hev-task.h"
#include "hev-task-system.h"
#include "hev-config.h"
#include "hev-config-const.h"
#include "hev-socks5-tproxy.h"

static void
show_help (const char *self_path)
{
    printf ("%s CONFIG_PATH\n", self_path);
    printf ("Version: %u.%u.%u\n", MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION);
}

int
main (int argc, char *argv[])
{
    if (2 != argc) {
        show_help (argv[0]);
        return -1;
    }

    if (0 > hev_config_init (argv[1]))
        return -2;

    if (0 > hev_socks5_tproxy_init ())
        return -3;

    hev_socks5_tproxy_run ();

    hev_socks5_tproxy_fini ();

    hev_config_fini ();

    return 0;
}

void
quit (void)
{
    hev_socks5_tproxy_stop ();
}
