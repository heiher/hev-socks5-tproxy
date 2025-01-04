/*
 ============================================================================
 Name        : hev-socket-factory.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Socket Factory
 ============================================================================
 */

#include <unistd.h>
#include <netinet/in.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

#include "hev-utils.h"
#include "hev-config.h"
#include "hev-logger.h"

#include "hev-socket-factory.h"

int
hev_socket_factory_tcp (int fd)
{
    int res;

    res = listen (fd, 100);
    if (res < 0) {
        LOG_E ("socket factory listen");
        return -1;
    }

    return 0;
}

int
hev_socket_factory_udp (int fd)
{
    int one = 1;
    int res;

    res = setsockopt (fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socket factory ipv4 orig dest");
        return -1;
    }

    res = setsockopt (fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socket factory ipv6 orig dest");
        return -1;
    }

    res = hev_config_get_misc_udp_recv_buffer_size ();
    res = setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &res, sizeof (res));
    if (res < 0)
        LOG_W ("socket factory socket rcvbuf");

    return 0;
}

int
hev_socket_factory_get (const char *addr, const char *port, int type,
                        int force_reuseport)
{
    struct sockaddr_in6 saddr;
    int one = 1;
    int res;
    int fd;

    LOG_D ("socket factory get");

    res = resolve_to_sockaddr (addr, port, type, &saddr);
    if (res < 0) {
        LOG_E ("socket factory resolve");
        goto exit;
    }

    fd = hev_task_io_socket_socket (AF_INET6, type, 0);
    if (fd < 0) {
        LOG_E ("socket factory socket");
        goto exit;
    }

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socket factory reuse addr");
        goto exit_close;
    }

    res = -1;
#ifdef SO_REUSEPORT
    res = setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof (one));
#endif
    if (res < 0 && force_reuseport) {
        LOG_E ("socket factory reuse port");
        goto exit_close;
    }

    res = setsockopt (fd, SOL_IP, IP_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socket factory ipv4 transparent");
        goto exit_close;
    }

    res = setsockopt (fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof (one));
    if (res < 0) {
        LOG_E ("socket factory ipv6 transparent");
        goto exit_close;
    }

    res = bind (fd, (struct sockaddr *)&saddr, sizeof (saddr));
    if (res < 0) {
        LOG_E ("socket factory bind");
        goto exit_close;
    }

    switch (type) {
    case SOCK_STREAM:
        res = hev_socket_factory_tcp (fd);
        break;
    case SOCK_DGRAM:
        res = hev_socket_factory_udp (fd);
        break;
    }
    if (res < 0)
        goto exit_close;

    return fd;

exit_close:
    close (fd);
exit:
    return -1;
}
