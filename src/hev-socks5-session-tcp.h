/*
 ============================================================================
 Name        : hev-socks5-session-tcp.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Socks5 Session TCP
 ============================================================================
 */

#ifndef __HEV_SOCKS5_SESSION_TCP_H__
#define __HEV_SOCKS5_SESSION_TCP_H__

#include <netinet/in.h>

#include "hev-list.h"

#include "hev-socks5-session.h"

#define HEV_SOCKS5_SESSION_TCP(p) ((HevSocks5SessionTCP *)p)
#define HEV_SOCKS5_SESSION_TCP_CLASS(p) ((HevSocks5SessionTCPClass *)p)

typedef struct _HevSocks5SessionTCP HevSocks5SessionTCP;
typedef struct _HevSocks5SessionTCPClass HevSocks5SessionTCPClass;

struct _HevSocks5SessionTCP
{
    HevSocks5Session base;

    HevListNode node;
    int fd;
};

struct _HevSocks5SessionTCPClass
{
    HevSocks5SessionClass base;
};

int hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self);
void hev_socks5_session_tcp_destruct (HevSocks5Session *base);

HevSocks5SessionTCP *hev_socks5_session_tcp_new (struct sockaddr *addr, int fd);

#endif /* __HEV_SOCKS5_SESSION_TCP_H__ */
