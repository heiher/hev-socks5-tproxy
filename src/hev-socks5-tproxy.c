/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 TProxy
 ============================================================================
 */

#include <signal.h>
#include <pthread.h>

#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-tsocks-cache.h"
#include "hev-socks5-worker.h"

#include "hev-socks5-tproxy.h"

static unsigned int workers;

static pthread_t *work_threads;
static HevSocks5Worker **worker_list;

static void
sigint_handler (int signum)
{
    hev_socks5_tproxy_stop ();
}

int
hev_socks5_tproxy_init (void)
{
    int res;

    LOG_D ("socks5 tproxy init");

    res = hev_task_system_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy task system");
        goto exit;
    }

    res = hev_tsocks_cache_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy tsocks cache");
        goto exit;
    }

    workers = hev_config_get_workers ();
    work_threads = hev_malloc0 (sizeof (pthread_t) * workers);
    if (!work_threads) {
        LOG_E ("socks5 tproxy work threads");
        goto exit;
    }

    worker_list = hev_malloc0 (sizeof (HevSocks5Worker *) * workers);
    if (!worker_list) {
        LOG_E ("socks5 tproxy worker list");
        goto exit;
    }

    signal (SIGPIPE, SIG_IGN);
    signal (SIGINT, sigint_handler);

    return 0;

exit:
    hev_socks5_tproxy_fini ();
    return -1;
}

void
hev_socks5_tproxy_fini (void)
{
    LOG_D ("socks5 tproxy fini");

    if (work_threads)
        hev_free (work_threads);
    if (worker_list)
        hev_free (worker_list);
    hev_tsocks_cache_fini ();
    hev_task_system_fini ();
}

static void *
work_thread_handler (void *data)
{
    HevSocks5Worker **worker = data;
    int res;

    res = hev_task_system_init ();
    if (res < 0) {
        LOG_E ("socks5 tproxy worker task system");
        goto exit;
    }

    res = hev_socks5_worker_init (*worker, 0);
    if (res < 0) {
        LOG_E ("socks5 tproxy worker init");
        goto free;
    }

    hev_socks5_worker_start (*worker);

    hev_task_system_run ();

    hev_socks5_worker_destroy (*worker);
    *worker = NULL;

free:
    hev_task_system_fini ();
exit:
    return NULL;
}

void
hev_socks5_tproxy_run (void)
{
    int res;
    int i;

    LOG_D ("socks5 tproxy run");

    worker_list[0] = hev_socks5_worker_new ();
    if (!worker_list[0]) {
        LOG_E ("socks5 tproxy worker");
        return;
    }

    res = hev_socks5_worker_init (worker_list[0], 1);
    if (res < 0) {
        LOG_E ("socks5 tproxy worker init");
        return;
    }

    hev_socks5_worker_start (worker_list[0]);

    for (i = 1; i < workers; i++) {
        worker_list[i] = hev_socks5_worker_new ();
        if (!worker_list[i]) {
            LOG_E ("socks5 tproxy worker");
            return;
        }

        pthread_create (&work_threads[i], NULL, work_thread_handler,
                        &worker_list[i]);
    }

    hev_task_system_run ();

    if (worker_list[0]) {
        int i;

        for (i = 1; i < workers; i++)
            pthread_join (work_threads[i], NULL);

        hev_socks5_worker_destroy (worker_list[0]);
        worker_list[0] = NULL;
    }
}

void
hev_socks5_tproxy_stop (void)
{
    int i;

    LOG_D ("socks5 tproxy stop");

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = worker_list[i];
        if (!worker)
            continue;

        hev_socks5_worker_stop (worker);
    }
}
