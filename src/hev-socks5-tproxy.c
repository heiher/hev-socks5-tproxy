/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2019 everyone.
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

#include "hev-socks5-tproxy.h"
#include "hev-socks5-worker.h"
#include "hev-config.h"
#include "hev-task.h"
#include "hev-task-io.h"
#include "hev-task-io-socket.h"
#include "hev-task-system.h"
#include "hev-memory-allocator.h"

typedef struct _HevSocks5WorkerData HevSocks5WorkerData;

struct _HevSocks5WorkerData
{
    int fd_tcp;
    int fd_dns;
    HevSocks5Worker *worker;
};

static unsigned int workers;
static HevSocks5WorkerData *worker_list;

static void sigint_handler (int signum);
static void *work_thread_handler (void *data);
static int hev_socks5_tproxy_tcp_socket (int *reuseport);
static int hev_socks5_tproxy_dns_socket (int *reuseport);

int
hev_socks5_tproxy_init (void)
{
    int i, reuseport = 1;
    HevSocks5WorkerData *wl;

    if (hev_task_system_init () < 0) {
        fprintf (stderr, "Init task system failed!\n");
        goto exit;
    }

    workers = hev_config_get_workers ();
    wl = hev_malloc0 (sizeof (HevSocks5WorkerData *) * workers);
    if (!wl) {
        fprintf (stderr, "Allocate worker list failed!\n");
        goto exit_free_sys;
    }

    if (signal (SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf (stderr, "Set signal pipe's handler failed!\n");
        goto exit_free_wl;
    }

    if (signal (SIGINT, sigint_handler) == SIG_ERR) {
        fprintf (stderr, "Set signal int's handler failed!\n");
        goto exit_free_wl;
    }

    wl[0].fd_tcp = hev_socks5_tproxy_tcp_socket (&reuseport);
    if ((wl[0].fd_tcp < 0) && (!reuseport))
        wl[0].fd_tcp = hev_socks5_tproxy_tcp_socket (&reuseport);
    wl[0].fd_dns = hev_socks5_tproxy_dns_socket (&reuseport);
    if ((wl[0].fd_tcp < 0) && (wl[0].fd_dns < 0)) {
        fprintf (stderr, "TCP and DNS listen failed!\n");
        goto exit_close_fds;
    }

    for (i = 1; i < workers; i++) {
        wl[i].fd_tcp = hev_socks5_tproxy_tcp_socket (&reuseport);
        if (wl[i].fd_tcp < 0)
            wl[i].fd_tcp = wl[0].fd_tcp;
        wl[i].fd_dns = hev_socks5_tproxy_dns_socket (&reuseport);
        if (wl[i].fd_dns < 0)
            wl[i].fd_dns = wl[0].fd_dns;
    }

    worker_list = wl;

    return 0;

exit_close_fds:
    if (wl[0].fd_tcp >= 0)
        close (wl[0].fd_tcp);
    if (wl[0].fd_dns >= 0)
        close (wl[0].fd_dns);
exit_free_wl:
    hev_free (wl);
exit_free_sys:
    hev_task_system_fini ();
exit:
    return -1;
}

void
hev_socks5_tproxy_fini (void)
{
    hev_free (worker_list);
    hev_task_system_fini ();
}

int
hev_socks5_tproxy_run (void)
{
    int i;
    pthread_t work_threads[workers];
    HevSocks5WorkerData *w0 = &worker_list[0];

    w0->worker = hev_socks5_worker_new (w0->fd_tcp, w0->fd_dns);
    if (!w0->worker) {
        fprintf (stderr, "Create socks5 worker 0 failed!\n");
        return -1;
    }

    hev_socks5_worker_start (w0->worker);

    for (i = 1; i < workers; i++) {
        pthread_create (&work_threads[i], NULL, work_thread_handler,
                        (void *)(intptr_t)i);
    }

    hev_task_system_run ();

    for (i = 1; i < workers; i++) {
        pthread_join (work_threads[i], NULL);
    }

    hev_socks5_worker_destroy (w0->worker);
    if (w0->fd_tcp >= 0)
        close (w0->fd_tcp);
    if (w0->fd_dns >= 0)
        close (w0->fd_dns);

    return 0;
}

void
hev_socks5_tproxy_stop (void)
{
    int i;

    for (i = 0; i < workers; i++) {
        HevSocks5WorkerData *wi = &worker_list[i];

        if (!wi->worker)
            continue;

        hev_socks5_worker_stop (wi->worker);
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
    HevSocks5WorkerData *wi = &worker_list[i];

    if (hev_task_system_init () < 0) {
        fprintf (stderr, "Init task system failed!\n");
        goto exit;
    }

    wi->worker = hev_socks5_worker_new (wi->fd_tcp, wi->fd_dns);
    if (!wi->worker) {
        fprintf (stderr, "Create socks5 worker %d failed!\n", i);
        goto exit_free_sys;
    }

    hev_socks5_worker_start (wi->worker);

    hev_task_system_run ();

    hev_socks5_worker_destroy (wi->worker);
    if (wi->fd_tcp >= 0)
        close (wi->fd_tcp);
    if (wi->fd_dns >= 0)
        close (wi->fd_dns);

exit_free_sys:
    hev_task_system_fini ();
exit:
    return NULL;
}

static int
hev_socks5_tproxy_tcp_socket (int *reuseport)
{
    int fd, ret, reuse = 1;
    struct sockaddr *addr;
    socklen_t addr_len;

    addr = hev_config_get_tcp_listen_address (&addr_len);
    if (!addr)
        goto exit;

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf (stderr, "Create socket failed!\n");
        goto exit;
    }

    ret = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse));
    if (ret == -1) {
        fprintf (stderr, "Set reuse address failed!\n");
        goto exit_close;
    }

    if (*reuseport) {
        ret = setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof (reuse));
        if (ret == -1) {
            *reuseport = 0;
            goto exit_close;
        }
    }

    ret = bind (fd, addr, addr_len);
    if (ret == -1) {
        fprintf (stderr, "Bind address failed!\n");
        goto exit_close;
    }
    ret = listen (fd, 100);
    if (ret == -1) {
        fprintf (stderr, "Listen failed!\n");
        goto exit_close;
    }

    return fd;

exit_close:
    close (fd);
exit:
    return -1;
}

static int
hev_socks5_tproxy_dns_socket (int *reuseport)
{
    int fd, ret, reuse = 1;
    struct sockaddr *addr;
    socklen_t addr_len;

    addr = hev_config_get_dns_listen_address (&addr_len);
    if (!addr)
        goto exit;

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf (stderr, "Create socket failed!\n");
        goto exit;
    }

    ret = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse));
    if (ret == -1) {
        fprintf (stderr, "Set reuse address failed!\n");
        goto exit_close;
    }

    if (*reuseport) {
        ret = setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof (reuse));
        if (ret == -1) {
            *reuseport = 0;
            goto exit_close;
        }
    }

    ret = bind (fd, addr, addr_len);
    if (ret == -1) {
        fprintf (stderr, "Bind address failed!\n");
        goto exit_close;
    }

    return fd;

exit_close:
    close (fd);
exit:
    return -1;
}
