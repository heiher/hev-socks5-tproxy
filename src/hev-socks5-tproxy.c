/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 TProxy
 ============================================================================
 */

#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-tsocks-cache.h"
#include "hev-socks5-worker.h"

#include "hev-socks5-tproxy.h"

enum
{
    SYNC_CONT = 1 << 0,
    SYNC_ABRT = 1 << 1,
    SYNC_SEND = 1 << 2,
    SYNC_SENT = 1 << 3,
    SYNC_WAIT = 1 << 4,
    SYNC_STOP = 1 << 5,
};

typedef struct _HevSocks5WorkerData HevSocks5WorkerData;

struct _HevSocks5WorkerData
{
    HevSocks5Worker *worker;
    pthread_t thread;
    int ts;
};

static atomic_int tsync;

static HevSocks5WorkerData *worker_list;

static void
sigint_handler (int signum)
{
    hev_socks5_tproxy_stop ();
}

static void *
work_thread_handler (void *data)
{
    HevSocks5Worker *worker = data;
    int res;

retry:
    res = atomic_load (&tsync);
    if (res & SYNC_ABRT) {
        goto exit;
    } else if (!(res & SYNC_CONT)) {
        usleep (500);
        goto retry;
    }

    res = hev_task_system_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy worker task system");
        goto exit;
    }

    hev_socks5_worker_start (worker);

    hev_task_system_run ();

    hev_task_system_fini ();
exit:
    return NULL;
}

int
hev_socks5_tproxy_init (void)
{
    int workers;
    int res;
    int i;

    LOG_D ("socks5 tproxy init");

    res = hev_task_system_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy task system");
        return -1;
    }

    res = hev_tsocks_cache_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy tsocks cache");
        hev_task_system_fini ();
        return -1;
    }

    workers = hev_config_get_workers ();
    worker_list = hev_malloc0 (sizeof (HevSocks5WorkerData) * workers);
    if (!worker_list) {
        LOG_E ("socks5 proxy worker list");
        goto exit;
    }

    atomic_fetch_and (&tsync, ~(SYNC_CONT | SYNC_ABRT));

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = hev_socks5_worker_new (i == 0);
        if (!worker) {
            LOG_E ("socks5 proxy worker %d", i);
            goto exit;
        }
        worker_list[i].worker = worker;

        /* Skip worker 0 */
        if (i == 0)
            continue;

        res = pthread_create (&worker_list[i].thread, NULL, work_thread_handler,
                              worker);
        if (res != 0) {
            LOG_E ("socks5 proxy worker %d thread", i);
            goto exit;
        }
        worker_list[i].ts = 1;
    }

    signal (SIGPIPE, SIG_IGN);
    signal (SIGINT, sigint_handler);
    atomic_fetch_or (&tsync, SYNC_SEND);

    return 0;

exit:
    hev_socks5_tproxy_fini ();
    return -1;
}

void
hev_socks5_tproxy_fini (void)
{
    int res;

    LOG_D ("socks5 tproxy fini");

retry:
    res = atomic_fetch_and (&tsync, ~(SYNC_SEND | SYNC_STOP | SYNC_SENT));
    if (res & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    if (worker_list) {
        int workers = hev_config_get_workers ();
        int i;

        for (i = 0; i < workers; i++) {
            if (worker_list[i].ts)
                pthread_join (worker_list[i].thread, NULL);
            if (worker_list[i].worker)
                hev_socks5_worker_destroy (worker_list[i].worker);
        }

        hev_free (worker_list);
        worker_list = NULL;
    }

    hev_tsocks_cache_fini ();
    hev_task_system_fini ();
}

void
hev_socks5_tproxy_run (void)
{
    LOG_D ("socks5 tproxy run");

    if (atomic_fetch_and (&tsync, ~SYNC_STOP) & SYNC_STOP)
        return;

    atomic_fetch_or (&tsync, SYNC_CONT);

    hev_socks5_worker_start (worker_list[0].worker);

    hev_task_system_run ();
}

void
hev_socks5_tproxy_stop (void)
{
    int res;

    LOG_D ("socks5 proxy stop");

retry:
    res = atomic_fetch_or (&tsync, SYNC_WAIT);
    if (res & SYNC_WAIT) {
        usleep (500);
        goto retry;
    }

    if (res & SYNC_SEND) {
        res = atomic_fetch_or (&tsync, SYNC_SENT);
        if (!(res & SYNC_SENT)) {
            int workers;
            int i;
            workers = hev_config_get_workers ();
            for (i = 0; i < workers; i++)
                hev_socks5_worker_stop (worker_list[i].worker);
        }
    } else {
        atomic_fetch_or (&tsync, SYNC_STOP | SYNC_ABRT);
    }

    atomic_fetch_and (&tsync, ~SYNC_WAIT);
}
