/*
 ============================================================================
 Name        : hev-socks5-worker.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2019 everyone.
 Description : Socks5 worker
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-worker.h"
#include "hev-socks5-session.h"
#include "hev-memory-allocator.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-task.h"
#include "hev-task-io.h"
#include "hev-task-io-socket.h"

#define TIMEOUT (30 * 1000)

struct _HevSocks5Worker
{
    int fd_tcp;
    int fd_dns;
    int event_fd;
    int quit;

    HevTask *task_worker_tcp;
    HevTask *task_worker_dns;
    HevTask *task_event;
    HevTask *task_session_manager;
    HevSocks5SessionBase *session_list;
};

static void hev_socks5_worker_tcp_task_entry (void *data);
static void hev_socks5_worker_dns_task_entry (void *data);
static void hev_socks5_event_task_entry (void *data);
static void hev_socks5_session_manager_task_entry (void *data);

static void session_manager_insert_session (HevSocks5Worker *self,
                                            HevSocks5Session *session);
static void session_manager_remove_session (HevSocks5Worker *self,
                                            HevSocks5Session *session);
static void session_close_handler (HevSocks5Session *session, void *data);

HevSocks5Worker *
hev_socks5_worker_new (int fd_tcp, int fd_dns)
{
    HevSocks5Worker *self;

    self = hev_malloc0 (sizeof (HevSocks5Worker));
    if (!self) {
        LOG_E ("Allocate worker failed!");
        goto exit;
    }

    self->fd_tcp = fd_tcp;
    self->fd_dns = fd_dns;
    self->event_fd = -1;

    if (fd_tcp >= 0) {
        self->task_worker_tcp = hev_task_new (8192);
        if (!self->task_worker_tcp) {
            LOG_E ("Create worker tcp's task failed!");
            goto exit_free;
        }
    }

    if (fd_dns >= 0) {
        self->task_worker_dns = hev_task_new (8192);
        if (!self->task_worker_dns) {
            LOG_E ("Create worker dns's task failed!");
            goto exit_free;
        }
    }

    self->task_event = hev_task_new (8192);
    if (!self->task_event) {
        LOG_E ("Create event's task failed!");
        goto exit_free;
    }

    self->task_session_manager = hev_task_new (8192);
    if (!self->task_session_manager) {
        LOG_E ("Create session manager's task failed!");
        goto exit_free_task_event;
    }

    return self;

exit_free_task_event:
    hev_task_unref (self->task_event);
exit_free:
    if (self->task_worker_tcp)
        hev_task_unref (self->task_worker_tcp);
    if (self->task_worker_dns)
        hev_task_unref (self->task_worker_dns);
    hev_free (self);
exit:
    return NULL;
}

void
hev_socks5_worker_destroy (HevSocks5Worker *self)
{
    hev_free (self);
}

void
hev_socks5_worker_start (HevSocks5Worker *self)
{
    if (self->task_worker_tcp)
        hev_task_run (self->task_worker_tcp, hev_socks5_worker_tcp_task_entry,
                      self);
    if (self->task_worker_dns)
        hev_task_run (self->task_worker_dns, hev_socks5_worker_dns_task_entry,
                      self);
    hev_task_run (self->task_event, hev_socks5_event_task_entry, self);
    hev_task_run (self->task_session_manager,
                  hev_socks5_session_manager_task_entry, self);
}

void
hev_socks5_worker_stop (HevSocks5Worker *self)
{
    if (self->event_fd == -1)
        return;

    if (eventfd_write (self->event_fd, 1) == -1)
        LOG_E ("Write stop event failed!");
}

static int
worker_task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5Worker *self = data;

    hev_task_yield (type);

    return (self->quit) ? -1 : 0;
}

static void
hev_socks5_worker_tcp_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevTask *task = hev_task_self ();

    hev_task_add_fd (task, self->fd_tcp, POLLIN);

    for (;;) {
        int client_fd;
        struct sockaddr_in6 addr6;
        struct sockaddr *addr = (struct sockaddr *)&addr6;
        socklen_t addr_len = sizeof (addr6);
        HevSocks5Session *s;

        client_fd = hev_task_io_socket_accept (self->fd_tcp, addr, &addr_len,
                                               worker_task_io_yielder, self);
        if (-1 == client_fd) {
            LOG_E ("Accept failed!");
            continue;
        } else if (-2 == client_fd) {
            break;
        }

        s = hev_socks5_session_new_tcp (client_fd, session_close_handler, self);
        if (!s) {
            close (client_fd);
            continue;
        }

        session_manager_insert_session (self, s);
        hev_socks5_session_run (s);
    }
}

static void
hev_socks5_worker_dns_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevTask *task = hev_task_self ();

    hev_task_add_fd (task, self->fd_dns, POLLIN);

    for (;;) {
        unsigned char buf[2048];
        ssize_t len;
        struct sockaddr_in6 addr6;
        struct sockaddr *addr = (struct sockaddr *)&addr6;
        socklen_t addr_len = sizeof (addr6);
        HevSocks5Session *s;

        len = recvfrom (self->fd_dns, buf, 2048, MSG_PEEK, addr, &addr_len);
        if (len == -1) {
            if (errno == EAGAIN) {
                hev_task_yield (HEV_TASK_WAITIO);
                if (self->quit)
                    break;
                continue;
            }

            LOG_E ("Receive failed!");
            break;
        }

        s = hev_socks5_session_new_dns (self->fd_dns, session_close_handler,
                                        self);
        if (!s)
            continue;

        session_manager_insert_session (self, s);
        hev_socks5_session_run (s);
    }
}

static void
hev_socks5_event_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevTask *task = hev_task_self ();
    ssize_t size;
    HevSocks5SessionBase *s;

    self->event_fd = eventfd (0, EFD_NONBLOCK);
    if (-1 == self->event_fd) {
        LOG_E ("Create eventfd failed!");
        return;
    }

    hev_task_add_fd (task, self->event_fd, POLLIN);

    for (;;) {
        eventfd_t val;
        size = eventfd_read (self->event_fd, &val);
        if (-1 == size && errno == EAGAIN) {
            hev_task_yield (HEV_TASK_WAITIO);
            continue;
        }
        break;
    }

    /* set quit flag */
    self->quit = 1;
    /* wakeup worker tcp's task */
    if (self->task_worker_tcp)
        hev_task_wakeup (self->task_worker_tcp);
    /* wakeup worker dns's task */
    if (self->task_worker_dns)
        hev_task_wakeup (self->task_worker_dns);
    /* wakeup session manager's task */
    hev_task_wakeup (self->task_session_manager);

    /* wakeup sessions's task */
    for (s = self->session_list; s; s = s->next) {
        s->hp = 0;

        /* wakeup s's task to do destroy */
        hev_task_wakeup (s->task);
    }

    close (self->event_fd);
}

static void
hev_socks5_session_manager_task_entry (void *data)
{
    HevSocks5Worker *self = data;

    for (;;) {
        HevSocks5SessionBase *s;

        hev_task_sleep (TIMEOUT);
        if (self->quit)
            break;

        for (s = self->session_list; s; s = s->next) {
            s->hp--;
            if (s->hp > 0)
                continue;

            /* wakeup s's task to do destroy */
            hev_task_wakeup (s->task);
        }
    }
}

static void
session_manager_insert_session (HevSocks5Worker *self, HevSocks5Session *s)
{
    HevSocks5SessionBase *session_base = (HevSocks5SessionBase *)s;

    /* insert session to session_list */
    session_base->prev = NULL;
    session_base->next = self->session_list;
    if (self->session_list)
        self->session_list->prev = session_base;
    self->session_list = session_base;
}

static void
session_manager_remove_session (HevSocks5Worker *self, HevSocks5Session *s)
{
    HevSocks5SessionBase *session_base = (HevSocks5SessionBase *)s;

    /* remove session from session_list */
    if (session_base->prev) {
        session_base->prev->next = session_base->next;
    } else {
        self->session_list = session_base->next;
    }
    if (session_base->next) {
        session_base->next->prev = session_base->prev;
    }
}

static void
session_close_handler (HevSocks5Session *s, void *data)
{
    HevSocks5Worker *self = data;

    session_manager_remove_session (self, s);
}
