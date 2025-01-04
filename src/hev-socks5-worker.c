/*
 ============================================================================
 Name        : hev-socks5-worker.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Socks5 Worker
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-pipe.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-socket-factory.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-session-udp.h"
#include "hev-tproxy-session-dns.h"

#include "hev-socks5-worker.h"

static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

struct _HevSocks5Worker
{
    int quit;
    int is_main;
    int event_fds[2];

    HevTask *task_tcp;
    HevTask *task_udp;
    HevTask *task_dns;
    HevTask *task_event;

    HevList tcp_set;
    HevList dns_set;
    HevRBTree udp_set;
};

static void
pthread_key_creator (void)
{
    pthread_key_create (&key, NULL);
}

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5Worker *self = data;

    hev_task_yield (type);

    return self->quit ? -1 : 0;
}

static HevSocks5Worker *
hev_socks5_worker_self (void)
{
    return pthread_getspecific (key);
}

static void
hev_socks5_tcp_session_task_entry (void *data)
{
    HevSocks5Worker *self = hev_socks5_worker_self ();
    HevSocks5SessionTCP *tcp = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (tcp));

    hev_list_del (&self->tcp_set, &tcp->node);
    hev_object_unref (HEV_OBJECT (tcp));
}

static void
hev_socks5_tcp_session_new (HevSocks5Worker *self, int fd)
{
    HevSocks5SessionTCP *tcp;
    struct sockaddr_in6 addr;
    socklen_t addrlen;
    int stack_size;
    HevTask *task;
    int res;

    LOG_D ("socks5 tcp session new");

    addrlen = sizeof (addr);
    res = getsockname (fd, (struct sockaddr *)&addr, &addrlen);
    if (res < 0) {
        LOG_E ("socks5 tcp orig dest");
        close (fd);
        return;
    }

    tcp = hev_socks5_session_tcp_new ((struct sockaddr *)&addr, fd);
    if (!tcp) {
        close (fd);
        return;
    }

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (tcp));
        return;
    }

    hev_tproxy_session_set_task (HEV_TPROXY_SESSION (tcp), task);
    hev_list_add_tail (&self->tcp_set, &tcp->node);
    hev_task_run (task, hev_socks5_tcp_session_task_entry, tcp);
}

static void
hev_socks5_tcp_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevListNode *node;
    const char *addr;
    const char *port;
    int fd;

    LOG_D ("socks5 tcp task run");

    addr = hev_config_get_tcp_address ();
    port = hev_config_get_tcp_port ();
    if (!addr)
        goto exit;

    fd = hev_socket_factory_get (addr, port, SOCK_STREAM, !self->is_main);
    if (fd < 0)
        goto exit;

    hev_task_add_fd (hev_task_self (), fd, POLLIN);

    for (;;) {
        int nfd;

        nfd = hev_task_io_socket_accept (fd, NULL, NULL, task_io_yielder, self);
        if (nfd == -1) {
            LOG_W ("socks5 tcp accept");
            continue;
        } else if (nfd < 0) {
            break;
        }

        hev_socks5_tcp_session_new (self, nfd);
    }

    node = hev_list_first (&self->tcp_set);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionTCP *tcp;

        tcp = container_of (node, HevSocks5SessionTCP, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (tcp));
    }

    close (fd);
exit:
    self->task_tcp = NULL;
}

static int
hev_socks5_udp_recvmsg (HevSocks5Worker *self, int fd, struct sockaddr *saddr,
                        struct sockaddr *daddr, void *buf, size_t len)
{
    union
    {
        char buf[CMSG_SPACE (sizeof (struct sockaddr_in6))];
        struct cmsghdr align;
    } u;
    struct msghdr mh = { 0 };
    struct iovec iov;
    int res;

    iov.iov_base = buf;
    iov.iov_len = len;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_name = saddr;
    mh.msg_namelen = sizeof (struct sockaddr_in6);
    mh.msg_control = u.buf;
    mh.msg_controllen = sizeof (u.buf);

    res = hev_task_io_socket_recvmsg (fd, &mh, 0, task_io_yielder, self);
    if (res < 0)
        return res;

    msg_to_sock_addr (&mh, daddr);

    return res;
}

static HevSocks5SessionUDP *
hev_socks5_udp_session_find (HevSocks5Worker *self, struct sockaddr *addr)
{
    HevRBTreeNode *node = self->udp_set.root;

    while (node) {
        HevSocks5SessionUDP *this;
        int res;

        this = container_of (node, HevSocks5SessionUDP, node);
        res = memcmp (&this->addr, addr, sizeof (struct sockaddr_in6));

        if (res < 0)
            node = node->left;
        else if (res > 0)
            node = node->right;
        else
            return this;
    }

    return NULL;
}

static void
hev_socks5_udp_session_add (HevSocks5Worker *self, HevSocks5SessionUDP *udp)
{
    HevRBTreeNode **new = &self->udp_set.root, *parent = NULL;

    while (*new) {
        HevSocks5SessionUDP *this;
        int res;

        this = container_of (*new, HevSocks5SessionUDP, node);
        res = memcmp (&this->addr, &udp->addr, sizeof (struct sockaddr_in6));

        parent = *new;
        if (res < 0)
            new = &((*new)->left);
        else if (res > 0)
            new = &((*new)->right);
    }

    hev_rbtree_node_link (&udp->node, parent, new);
    hev_rbtree_insert_color (&self->udp_set, &udp->node);
}

static void
hev_socks5_udp_session_del (HevSocks5Worker *self, HevSocks5SessionUDP *udp)
{
    hev_rbtree_erase (&self->udp_set, &udp->node);
}

static void
hev_socks5_udp_session_task_entry (void *data)
{
    HevSocks5Worker *self = hev_socks5_worker_self ();
    HevSocks5SessionUDP *udp = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (udp));

    hev_socks5_udp_session_del (self, udp);
    hev_object_unref (HEV_OBJECT (udp));
}

static HevSocks5SessionUDP *
hev_socks5_udp_session_new (HevSocks5Worker *self, struct sockaddr *addr)
{
    HevSocks5SessionUDP *udp;
    int stack_size;
    HevTask *task;

    LOG_D ("socks5 udp session new");

    udp = hev_socks5_session_udp_new (addr);
    if (!udp)
        return NULL;

    stack_size = hev_config_get_misc_task_stack_size ();
    task = hev_task_new (stack_size);
    if (!task) {
        hev_object_unref (HEV_OBJECT (udp));
        return NULL;
    }

    hev_tproxy_session_set_task (HEV_TPROXY_SESSION (udp), task);
    hev_socks5_udp_session_add (self, udp);
    hev_task_run (task, hev_socks5_udp_session_task_entry, udp);

    return udp;
}

static int
hev_socks5_udp_dispatch (HevSocks5Worker *self, struct sockaddr *saddr,
                         struct sockaddr *daddr, void *data, size_t len)
{
    HevSocks5SessionUDP *udp;
    int res;

    udp = hev_socks5_udp_session_find (self, saddr);
    if (!udp) {
        udp = hev_socks5_udp_session_new (self, saddr);
        if (!udp)
            return -1;
    }

    res = hev_socks5_session_udp_send (udp, data, len, daddr);

    return res;
}

static void
hev_socks5_udp_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevRBTreeNode *node;
    const char *addr;
    const char *port;
    int fd;

    LOG_D ("socks5 udp task run");

    addr = hev_config_get_udp_address ();
    port = hev_config_get_udp_port ();
    if (!addr)
        goto exit;

    fd = hev_socket_factory_get (addr, port, SOCK_DGRAM, !self->is_main);
    if (fd < 0)
        goto exit;

    hev_task_add_fd (hev_task_self (), fd, POLLIN);

    for (;;) {
        struct sockaddr_in6 saddr = { 0 };
        struct sockaddr_in6 daddr = { 0 };
        struct sockaddr *sap;
        struct sockaddr *dap;
        void *buf;
        int res;

        buf = hev_malloc (UDP_BUF_SIZE);
        sap = (struct sockaddr *)&saddr;
        dap = (struct sockaddr *)&daddr;

        res = hev_socks5_udp_recvmsg (self, fd, sap, dap, buf, UDP_BUF_SIZE);
        if (res == -1 || res == 0) {
            LOG_W ("socks5 udp recvmsg");
            hev_free (buf);
            continue;
        } else if (res < 0) {
            hev_free (buf);
            break;
        }

        res = hev_socks5_udp_dispatch (self, sap, dap, buf, res);
        if (res < 0)
            hev_free (buf);
    }

    node = hev_rbtree_first (&self->udp_set);
    for (; node; node = hev_rbtree_node_next (node)) {
        HevSocks5SessionUDP *udp;

        udp = container_of (node, HevSocks5SessionUDP, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (udp));
    }

    close (fd);
exit:
    self->task_udp = NULL;
}

static void
hev_socks5_dns_session_task_entry (void *data)
{
    HevSocks5Worker *self = hev_socks5_worker_self ();
    HevTProxySessionDNS *dns = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (dns));

    hev_list_del (&self->dns_set, &dns->node);
    hev_object_unref (HEV_OBJECT (dns));
}

static void
hev_socks5_dns_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    HevListNode *node;
    const char *addr;
    const char *port;
    int stack_size;
    int fd;

    LOG_D ("socks5 dns task run");

    addr = hev_config_get_dns_address ();
    port = hev_config_get_dns_port ();
    if (!addr)
        goto exit;

    fd = hev_socket_factory_get (addr, port, SOCK_DGRAM, !self->is_main);
    if (fd < 0)
        goto exit;

    hev_task_add_fd (hev_task_self (), fd, POLLIN);
    stack_size = hev_config_get_misc_task_stack_size ();

    for (;;) {
        HevTProxySessionDNS *dns;
        struct sockaddr *sap;
        struct sockaddr *dap;
        HevTask *task;
        void *buffer;
        int res;

        dns = hev_tproxy_session_dns_new ();
        sap = hev_tproxy_session_dns_get_saddr (dns);
        dap = hev_tproxy_session_dns_get_daddr (dns);
        buffer = hev_tproxy_session_dns_get_buffer (dns);

        res = hev_socks5_udp_recvmsg (self, fd, sap, dap, buffer, UDP_BUF_SIZE);
        if (res == -1 || res == 0) {
            LOG_W ("socks5 dns recvmsg");
            hev_object_unref (HEV_OBJECT (dns));
            continue;
        } else if (res <= 0) {
            hev_object_unref (HEV_OBJECT (dns));
            break;
        }

        task = hev_task_new (stack_size);
        hev_task_run (task, hev_socks5_dns_session_task_entry, dns);
        hev_list_add_tail (&self->dns_set, &dns->node);
        hev_tproxy_session_dns_set_size (dns, res);
        hev_tproxy_session_set_task (HEV_TPROXY_SESSION (dns), task);
    }

    node = hev_list_first (&self->dns_set);
    for (; node; node = hev_list_node_next (node)) {
        HevTProxySessionDNS *dns;

        dns = container_of (node, HevTProxySessionDNS, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (dns));
    }

    close (fd);
exit:
    self->task_dns = NULL;
}

static void
hev_socks5_event_task_entry (void *data)
{
    HevSocks5Worker *self = data;
    int res;

    LOG_D ("socks5 event task run");

    res = hev_task_io_pipe_pipe (self->event_fds);
    if (res < 0) {
        LOG_E ("socks5 proxy pipe");
        return;
    }

    hev_task_add_fd (hev_task_self (), self->event_fds[0], POLLIN);

    for (;;) {
        char val;

        res = hev_task_io_read (self->event_fds[0], &val, sizeof (val), NULL,
                                NULL);
        if (res < sizeof (val))
            continue;

        break;
    }

    self->quit = 1;

    if (self->task_tcp)
        hev_task_wakeup (self->task_tcp);
    if (self->task_udp)
        hev_task_wakeup (self->task_udp);
    if (self->task_dns)
        hev_task_wakeup (self->task_dns);

    close (self->event_fds[0]);
    close (self->event_fds[1]);
}

HevSocks5Worker *
hev_socks5_worker_new (void)
{
    HevSocks5Worker *self;

    self = calloc (1, sizeof (HevSocks5Worker));
    if (!self)
        return NULL;

    LOG_D ("%p socks5 worker new", self);

    self->event_fds[0] = -1;
    self->event_fds[1] = -1;

    pthread_once (&key_once, pthread_key_creator);

    return self;
}

void
hev_socks5_worker_destroy (HevSocks5Worker *self)
{
    LOG_D ("%p works worker destroy", self);

    free (self);
}

int
hev_socks5_worker_init (HevSocks5Worker *self, int is_main)
{
    LOG_D ("%p works worker init", self);

    self->task_event = hev_task_new (-1);
    if (!self->task_event) {
        LOG_E ("socks5 worker task event");
        goto exit;
    }

    self->task_tcp = hev_task_new (-1);
    if (!self->task_tcp) {
        LOG_E ("socks5 worker task tcp");
        goto free_event;
    }

    self->task_udp = hev_task_new (-1);
    if (!self->task_udp) {
        LOG_E ("socks5 worker task udp");
        goto free_tcp;
    }

    self->task_dns = hev_task_new (-1);
    if (!self->task_dns) {
        LOG_E ("socks5 worker task dns");
        goto free_udp;
    }

    self->is_main = is_main;
    pthread_setspecific (key, self);

    return 0;

free_udp:
    hev_task_unref (self->task_udp);
free_tcp:
    hev_task_unref (self->task_tcp);
free_event:
    hev_task_unref (self->task_event);
exit:
    return -1;
}

void
hev_socks5_worker_start (HevSocks5Worker *self)
{
    LOG_D ("%p works worker start", self);

    hev_task_run (self->task_event, hev_socks5_event_task_entry, self);

    if (self->task_tcp)
        hev_task_run (self->task_tcp, hev_socks5_tcp_task_entry, self);

    if (self->task_udp)
        hev_task_run (self->task_udp, hev_socks5_udp_task_entry, self);

    if (self->task_dns)
        hev_task_run (self->task_dns, hev_socks5_dns_task_entry, self);
}

void
hev_socks5_worker_stop (HevSocks5Worker *self)
{
    char val = 's';

    LOG_D ("%p works worker stop", self);

    if (self->event_fds[1] < 0)
        return;

    val = write (self->event_fds[1], &val, sizeof (val));
    if (val < 0)
        LOG_E ("socks5 proxy write event");
}
