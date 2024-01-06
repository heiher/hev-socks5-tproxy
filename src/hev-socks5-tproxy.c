/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 TProxy
 ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/eventfd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>

#include "hev-list.h"
#include "hev-utils.h"
#include "hev-rbtree.h"
#include "hev-config.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-config-const.h"
#include "hev-tsocks-cache.h"
#include "hev-socks5-session-tcp.h"
#include "hev-socks5-session-udp.h"
#include "hev-tproxy-session-dns.h"

#include "hev-socks5-tproxy.h"

static int quit;
static int fd_event;

static HevList tcp_set;
static HevList dns_set;
static HevRBTree udp_set;

static HevTask *task_tcp;
static HevTask *task_udp;
static HevTask *task_dns;
static HevTask *task_event;

static void
sigint_handler (int signum)
{
    hev_socks5_tproxy_stop ();
}

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    hev_task_yield (type);

    return quit ? -1 : 0;
}

static int
hev_socks5_tproxy_tcp_socket (void)
{
    struct sockaddr_in6 saddr;
    const char *addr;
    const char *port;
    int one = 1;
    int res;
    int fd;

    LOG_D ("socks5 tproxy tcp socket");

    addr = hev_config_get_tcp_address ();
    port = hev_config_get_tcp_port ();
    if (!addr)
        goto exit;

    res = resolve_to_sockaddr (addr, port, SOCK_STREAM, &saddr);
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp addr");
        goto exit;
    }

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_E ("socks5 tproxy tcp socket");
        goto exit;
    }

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp socket reuse");
        goto close;
    }

    res = setsockopt (fd, SOL_IP, IP_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp ipv4 transparent");
        goto close;
    }

    res = setsockopt (fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp ipv6 transparent");
        goto close;
    }

    res = bind (fd, (struct sockaddr *)&saddr, sizeof (saddr));
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp socket bind");
        goto close;
    }

    res = listen (fd, 100);
    if (res < 0) {
        LOG_E ("socks5 tproxy tcp socket listen");
        goto close;
    }

    return fd;

close:
    close (fd);
exit:
    return -1;
}

static int
hev_socks5_tproxy_udp_socket (const char *addr, const char *port)
{
    struct sockaddr_in6 saddr;
    int one = 1;
    int res;
    int fd;

    LOG_D ("socks5 tproxy udp socket");

    res = resolve_to_sockaddr (addr, port, SOCK_DGRAM, &saddr);
    if (res < 0) {
        LOG_E ("socks5 tproxy udp addr");
        goto exit;
    }

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_E ("socks5 tproxy udp socket");
        goto exit;
    }

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp socket reuse");
        goto close;
    }

    res = setsockopt (fd, SOL_IP, IP_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp ipv4 transparent");
        goto close;
    }

    res = setsockopt (fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp ipv6 transparent");
        goto close;
    }

    res = setsockopt (fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp ipv4 orig dest");
        goto close;
    }

    res = setsockopt (fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp ipv6 orig dest");
        goto close;
    }

    res = hev_config_get_misc_udp_recv_buffer_size ();
    res = setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &res, sizeof (res));
    if (res < 0)
        LOG_W ("socks5 tproxy udp socket rcvbuf");

    res = bind (fd, (struct sockaddr *)&saddr, sizeof (saddr));
    if (res < 0) {
        LOG_E ("socks5 tproxy udp socket bind");
        goto close;
    }

    return fd;

close:
    close (fd);
exit:
    return -1;
}

static void
hev_socks5_event_task_entry (void *data)
{
    eventfd_t val;

    LOG_D ("socks5 event task run");

    fd_event = eventfd (0, EFD_NONBLOCK);
    if (fd_event < 0) {
        LOG_E ("socks5 eventfd");
        return;
    }

    hev_task_add_fd (hev_task_self (), fd_event, POLLIN);
    hev_task_io_read (fd_event, &val, sizeof (val), NULL, NULL);

    quit = 1;

    if (task_tcp)
        hev_task_wakeup (task_tcp);
    if (task_udp)
        hev_task_wakeup (task_udp);
    if (task_dns)
        hev_task_wakeup (task_dns);

    close (fd_event);
    fd_event = -1;
    task_event = NULL;
}

static void
hev_socks5_tcp_session_task_entry (void *data)
{
    HevSocks5SessionTCP *tcp = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (tcp));

    hev_list_del (&tcp_set, &tcp->node);
    hev_object_unref (HEV_OBJECT (tcp));
}

static void
hev_socks5_tcp_session_new (int fd)
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
    hev_list_add_tail (&tcp_set, &tcp->node);
    hev_task_run (task, hev_socks5_tcp_session_task_entry, tcp);
}

static void
hev_socks5_tcp_task_entry (void *data)
{
    HevListNode *node;
    int fd;

    LOG_D ("socks5 tcp task run");

    fd = hev_socks5_tproxy_tcp_socket ();
    if (fd < 0)
        goto exit;

    hev_task_add_fd (hev_task_self (), fd, POLLIN);

    for (;;) {
        int nfd;

        nfd = hev_task_io_socket_accept (fd, NULL, NULL, task_io_yielder, NULL);
        if (nfd == -1) {
            LOG_W ("socks5 tcp accept");
            continue;
        } else if (nfd < 0) {
            break;
        }

        hev_socks5_tcp_session_new (nfd);
    }

    node = hev_list_first (&tcp_set);
    for (; node; node = hev_list_node_next (node)) {
        HevSocks5SessionTCP *tcp;

        tcp = container_of (node, HevSocks5SessionTCP, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (tcp));
    }

    close (fd);
exit:
    task_tcp = NULL;
}

static int
hev_socks5_udp_recvmsg (int fd, struct sockaddr *saddr, struct sockaddr *daddr,
                        void *buf, size_t len)
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

    res = hev_task_io_socket_recvmsg (fd, &mh, 0, task_io_yielder, NULL);
    if (res < 0)
        return res;

    msg_to_sock_addr (&mh, daddr);

    return res;
}

static HevSocks5SessionUDP *
hev_socks5_udp_session_find (struct sockaddr *addr)
{
    HevRBTreeNode *node = udp_set.root;

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
hev_socks5_udp_session_add (HevSocks5SessionUDP *udp)
{
    HevRBTreeNode **new = &udp_set.root, *parent = NULL;

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
    hev_rbtree_insert_color (&udp_set, &udp->node);
}

static void
hev_socks5_udp_session_del (HevSocks5SessionUDP *udp)
{
    hev_rbtree_erase (&udp_set, &udp->node);
}

static void
hev_socks5_udp_session_task_entry (void *data)
{
    HevSocks5SessionUDP *udp = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (udp));

    hev_socks5_udp_session_del (udp);
    hev_object_unref (HEV_OBJECT (udp));
}

static HevSocks5SessionUDP *
hev_socks5_udp_session_new (struct sockaddr *addr)
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
    hev_socks5_udp_session_add (udp);
    hev_task_run (task, hev_socks5_udp_session_task_entry, udp);

    return udp;
}

static int
hev_socks5_udp_dispatch (struct sockaddr *saddr, struct sockaddr *daddr,
                         void *data, size_t len)
{
    HevSocks5SessionUDP *udp;
    int res;

    udp = hev_socks5_udp_session_find (saddr);
    if (!udp) {
        udp = hev_socks5_udp_session_new (saddr);
        if (!udp)
            return -1;
    }

    res = hev_socks5_session_udp_send (udp, data, len, daddr);

    return res;
}

static void
hev_socks5_udp_task_entry (void *data)
{
    HevRBTreeNode *node;
    const char *addr;
    const char *port;
    int fd;

    LOG_D ("socks5 udp task run");

    addr = hev_config_get_udp_address ();
    port = hev_config_get_udp_port ();
    if (!addr)
        goto exit;

    fd = hev_socks5_tproxy_udp_socket (addr, port);
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

        res = hev_socks5_udp_recvmsg (fd, sap, dap, buf, UDP_BUF_SIZE);
        if (res == -1 || res == 0) {
            LOG_W ("socks5 udp recvmsg");
            hev_free (buf);
            continue;
        } else if (res < 0) {
            hev_free (buf);
            break;
        }

        res = hev_socks5_udp_dispatch (sap, dap, buf, res);
        if (res < 0)
            hev_free (buf);
    }

    node = hev_rbtree_first (&udp_set);
    for (; node; node = hev_rbtree_node_next (node)) {
        HevSocks5SessionUDP *udp;

        udp = container_of (node, HevSocks5SessionUDP, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (udp));
    }

    close (fd);
exit:
    task_udp = NULL;
}

static void
hev_socks5_dns_session_task_entry (void *data)
{
    HevTProxySessionDNS *dns = data;

    hev_tproxy_session_run (HEV_TPROXY_SESSION (dns));

    hev_list_del (&dns_set, &dns->node);
    hev_object_unref (HEV_OBJECT (dns));
}

static void
hev_socks5_dns_task_entry (void *data)
{
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

    fd = hev_socks5_tproxy_udp_socket (addr, port);
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

        res = hev_socks5_udp_recvmsg (fd, sap, dap, buffer, UDP_BUF_SIZE);
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
        hev_list_add_tail (&dns_set, &dns->node);
        hev_tproxy_session_dns_set_size (dns, res);
        hev_tproxy_session_set_task (HEV_TPROXY_SESSION (dns), task);
    }

    node = hev_list_first (&dns_set);
    for (; node; node = hev_list_node_next (node)) {
        HevTProxySessionDNS *dns;

        dns = container_of (node, HevTProxySessionDNS, node);
        hev_tproxy_session_terminate (HEV_TPROXY_SESSION (dns));
    }

    close (fd);
exit:
    task_dns = NULL;
}

int
hev_socks5_tproxy_init (void)
{
    LOG_D ("socks5 tproxy init");

    if (hev_task_system_init () < 0) {
        LOG_E ("socks5 tproxy task system");
        goto exit;
    }

    if (hev_tsocks_cache_init () < 0) {
        LOG_E ("socks5 tproxy tsocks cache");
        goto exit;
    }

    task_event = hev_task_new (-1);
    if (!task_event) {
        LOG_E ("socks5 tproxy task event");
        goto exit;
    }

    task_tcp = hev_task_new (-1);
    if (!task_tcp) {
        LOG_E ("socks5 tproxy task tcp");
        goto exit;
    }

    task_udp = hev_task_new (-1);
    if (!task_udp) {
        LOG_E ("socks5 tproxy task udp");
        goto exit;
    }

    task_dns = hev_task_new (-1);
    if (!task_dns) {
        LOG_E ("socks5 tproxy task dns");
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

    if (task_event)
        hev_task_unref (task_event);
    if (task_tcp)
        hev_task_unref (task_tcp);
    if (task_udp)
        hev_task_unref (task_udp);
    if (task_dns)
        hev_task_unref (task_dns);

    hev_tsocks_cache_fini ();
    hev_task_system_fini ();
}

void
hev_socks5_tproxy_run (void)
{
    LOG_D ("socks5 tproxy run");

    hev_task_run (task_event, hev_socks5_event_task_entry, NULL);

    if (task_tcp)
        hev_task_run (task_tcp, hev_socks5_tcp_task_entry, NULL);

    if (task_udp)
        hev_task_run (task_udp, hev_socks5_udp_task_entry, NULL);

    if (task_dns)
        hev_task_run (task_dns, hev_socks5_dns_task_entry, NULL);

    hev_task_system_run ();
}

void
hev_socks5_tproxy_stop (void)
{
    LOG_D ("socks5 tproxy stop");

    if (fd_event < 0)
        return;

    if (eventfd_write (fd_event, 1) < 0)
        LOG_E ("socks5 tproxy write event");
}
