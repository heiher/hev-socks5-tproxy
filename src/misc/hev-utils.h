/*
 ============================================================================
 Name        : hev-utils.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Utils
 ============================================================================
 */

#ifndef __HEV_UTILS_H__
#define __HEV_UTILS_H__

#include <netinet/in.h>

void run_as_daemon (const char *pid_file);
int set_limit_nofile (int limit_nofile);
int set_sock_mark (int fd, unsigned int mark);
void msg_to_sock_addr (struct msghdr *msg, struct sockaddr *addr);
int resolve_to_sockaddr (const char *addr, const char *port, int type,
                         struct sockaddr_in6 *saddr);

#endif /* __HEV_UTILS_H__ */
