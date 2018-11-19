/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description : Socks5 tproxy
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-tproxy.h"
#include "hev-socks5-worker.h"
#include "hev-config.h"
#include "hev-task.h"
#include "hev-task-io.h"
#include "hev-task-io-socket.h"
#include "hev-task-system.h"
#include "hev-memory-allocator.h"

static int fd_tcp = -1;
static int fd_dns = -1;
static unsigned int workers;
static HevSocks5Worker **worker_list;

static void sigint_handler (int signum);
static void *work_thread_handler (void *data);
static int hev_socks5_tproxy_tcp_init (void);
static int hev_socks5_tproxy_dns_init (void);

int
hev_socks5_tproxy_init (void)
{
    if (hev_task_system_init () < 0) {
        fprintf (stderr, "Init task system failed!\n");
        return -1;
    }

    fd_tcp = hev_socks5_tproxy_tcp_init ();
    fd_dns = hev_socks5_tproxy_dns_init ();
    if (fd_tcp < 0 && fd_dns < 0) {
        fprintf (stderr, "TCP and DNS listen failed!\n");
        return -2;
    }

    if (signal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf (stderr, "Set signal pipe's handler failed!\n");
        if (fd_tcp >= 0)
            close (fd_tcp);
        if (fd_dns >= 0)
            close (fd_dns);
        return -3;
    }

    if (signal (SIGINT, sigint_handler) == SIG_ERR) {
        fprintf (stderr, "Set signal int's handler failed!\n");
        if (fd_tcp >= 0)
            close (fd_tcp);
        if (fd_dns >= 0)
            close (fd_dns);
        return -4;
    }

    workers = hev_config_get_workers ();
    worker_list = hev_malloc0 (sizeof (HevSocks5Worker *) * workers);
    if (!worker_list) {
        fprintf (stderr, "Allocate worker list failed!\n");
        if (fd_tcp >= 0)
            close (fd_tcp);
        if (fd_dns >= 0)
            close (fd_dns);
        return -5;
    }

    return 0;
}

void
hev_socks5_tproxy_fini (void)
{
    hev_free (worker_list);
    if (fd_tcp >= 0)
        close (fd_tcp);
    if (fd_dns >= 0)
        close (fd_dns);
    hev_task_system_fini ();
}

int
hev_socks5_tproxy_run (void)
{
    int i;
    pthread_t work_threads[workers];

    worker_list[0] = hev_socks5_worker_new (fd_tcp, fd_dns);
    if (!worker_list[0]) {
        fprintf (stderr, "Create socks5 worker 0 failed!\n");
        return -1;
    }

    hev_socks5_worker_start (worker_list[0]);

    for (i = 1; i < workers; i++) {
        pthread_create (&work_threads[i], NULL, work_thread_handler,
                        (void *)(intptr_t)i);
    }

    hev_task_system_run ();

    for (i = 1; i < workers; i++) {
        pthread_join (work_threads[i], NULL);
    }

    hev_socks5_worker_destroy (worker_list[0]);

    return 0;
}

void
hev_socks5_tproxy_stop (void)
{
    int i;

    for (i = 0; i < workers; i++) {
        if (!worker_list[i])
            continue;

        hev_socks5_worker_stop (worker_list[i]);
    }
}

static void
sigint_handler (int signum)
{
    hev_socks5_tproxy_stop ();
}

static void *
work_thread_handler (void *data)
{
    int i = (intptr_t)data;

    if (hev_task_system_init () < 0) {
        fprintf (stderr, "Init task system failed!\n");
        return NULL;
    }

    worker_list[i] = hev_socks5_worker_new (fd_tcp, fd_dns);
    if (!worker_list[i]) {
        fprintf (stderr, "Create socks5 worker %d failed!\n", i);
        hev_task_system_fini ();
        return NULL;
    }

    hev_socks5_worker_start (worker_list[i]);

    hev_task_system_run ();

    hev_socks5_worker_destroy (worker_list[i]);

    hev_task_system_fini ();

    return NULL;
}

static int
hev_socks5_tproxy_tcp_init (void)
{
    int ret, fd, reuseaddr = 1;
    struct sockaddr_in addr;
    const char *address;

    address = hev_config_get_tcp_listen_address ();
    if (!address[0]) {
        return -1;
    }

    fd = hev_task_io_socket_socket (AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf (stderr, "Create socket failed!\n");
        return -2;
    }

    ret = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                      sizeof (reuseaddr));
    if (ret == -1) {
        fprintf (stderr, "Set reuse address failed!\n");
        close (fd);
        return -3;
    }

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr (address);
    addr.sin_port = htons (hev_config_get_tcp_port ());
    ret = bind (fd, (struct sockaddr *)&addr, (socklen_t)sizeof (addr));
    if (ret == -1) {
        fprintf (stderr, "Bind address failed!\n");
        close (fd);
        return -4;
    }
    ret = listen (fd, 100);
    if (ret == -1) {
        fprintf (stderr, "Listen failed!\n");
        close (fd);
        return -5;
    }

    return fd;
}

static int
hev_socks5_tproxy_dns_init (void)
{
    int ret, fd, reuseaddr = 1;
    struct sockaddr_in addr;
    const char *address;

    address = hev_config_get_dns_listen_address ();
    if (!address[0]) {
        return -1;
    }

    fd = hev_task_io_socket_socket (AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf (stderr, "Create socket failed!\n");
        return -2;
    }

    ret = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                      sizeof (reuseaddr));
    if (ret == -1) {
        fprintf (stderr, "Set reuse address failed!\n");
        close (fd);
        return -3;
    }

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr (address);
    addr.sin_port = htons (hev_config_get_dns_port ());
    ret = bind (fd, (struct sockaddr *)&addr, (socklen_t)sizeof (addr));
    if (ret == -1) {
        fprintf (stderr, "Bind address failed!\n");
        close (fd);
        return -4;
    }

    return fd;
}
