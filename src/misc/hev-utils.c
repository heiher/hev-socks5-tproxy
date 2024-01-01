/*
 ============================================================================
 Name        : hev-utils.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Utils
 ============================================================================
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <hev-task-dns.h>

#include "hev-logger.h"

#include "hev-utils.h"

void
run_as_daemon (const char *pid_file)
{
    FILE *fp;

    fp = fopen (pid_file, "w+");
    if (!fp) {
        LOG_E ("open pid file %s", pid_file);
        return;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if (daemon (0, 0)) {
        /* ignore return value */
    }
#pragma GCC diagnostic pop

    fprintf (fp, "%u\n", getpid ());
    fclose (fp);
}

int
set_limit_nofile (int limit_nofile)
{
    struct rlimit limit = {
        .rlim_cur = limit_nofile,
        .rlim_max = limit_nofile,
    };

    return setrlimit (RLIMIT_NOFILE, &limit);
}

int
set_sock_mark (int fd, unsigned int mark)
{
#if defined(__linux__)
    return setsockopt (fd, SOL_SOCKET, SO_MARK, &mark, sizeof (mark));
#elif defined(__FreeBSD__)
    return setsockopt (fd, SOL_SOCKET, SO_USER_COOKIE, &mark, sizeof (mark));
#endif
    return 0;
}

void
msg_to_sock_addr (struct msghdr *msg, struct sockaddr *addr)
{
    struct cmsghdr *cm;

    for (cm = CMSG_FIRSTHDR (msg); cm; cm = CMSG_NXTHDR (msg, cm)) {
        if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_ORIGDSTADDR) {
            struct sockaddr_in6 *dap;
            struct sockaddr_in *sap;

            dap = (struct sockaddr_in6 *)addr;
            sap = (struct sockaddr_in *)CMSG_DATA (cm);

            dap->sin6_family = AF_INET6;
            dap->sin6_port = sap->sin_port;
            memset (&dap->sin6_addr, 0, 10);
            dap->sin6_addr.s6_addr[10] = 0xff;
            dap->sin6_addr.s6_addr[11] = 0xff;
            memcpy (&dap->sin6_addr.s6_addr[12], &sap->sin_addr, 4);
            break;
        }
        if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_ORIGDSTADDR) {
            struct sockaddr_in6 *dap;
            struct sockaddr_in *sap;

            dap = (struct sockaddr_in6 *)addr;
            sap = (struct sockaddr_in *)CMSG_DATA (cm);

            memcpy (dap, sap, sizeof (struct sockaddr_in6));
            break;
        }
    }
}

int
resolve_to_sockaddr (const char *addr, const char *port, int type,
                     struct sockaddr_in6 *saddr)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result;
    int res;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_flags = AI_PASSIVE;

    res = hev_task_dns_getaddrinfo (addr, port, &hints, &result);
    if (res < 0)
        return -1;

    if (result->ai_family == AF_INET) {
        struct sockaddr_in *adp;

        adp = (struct sockaddr_in *)result->ai_addr;
        saddr->sin6_family = AF_INET6;
        saddr->sin6_port = adp->sin_port;
        memset (&saddr->sin6_addr, 0, 10);
        saddr->sin6_addr.s6_addr[10] = 0xff;
        saddr->sin6_addr.s6_addr[11] = 0xff;
        memcpy (&saddr->sin6_addr.s6_addr[12], &adp->sin_addr, 4);
    } else if (result->ai_family == AF_INET6) {
        memcpy (saddr, result->ai_addr, sizeof (*saddr));
    }

    freeaddrinfo (result);

    return 0;
}
