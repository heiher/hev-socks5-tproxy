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

#include "hev-socks5-client-tcp.h"

#include "hev-socks5-session.h"

#define HEV_SOCKS5_SESSION_TCP(p) ((HevSocks5SessionTCP *)p)
#define HEV_SOCKS5_SESSION_TCP_CLASS(p) ((HevSocks5SessionTCPClass *)p)
#define HEV_SOCKS5_SESSION_TCP_TYPE (hev_socks5_session_tcp_class ())

typedef struct _HevSocks5SessionTCP HevSocks5SessionTCP;
typedef struct _HevSocks5SessionTCPClass HevSocks5SessionTCPClass;

struct _HevSocks5SessionTCP
{
    HevSocks5ClientTCP base;

    HevTask *task;
    HevListNode node;
    int fd;
};

struct _HevSocks5SessionTCPClass
{
    HevSocks5ClientTCPClass base;

    HevSocks5SessionIface session;
};

HevObjectClass *hev_socks5_session_tcp_class (void);

int hev_socks5_session_tcp_construct (HevSocks5SessionTCP *self,
                                      struct sockaddr *addr, int fd);

HevSocks5SessionTCP *hev_socks5_session_tcp_new (struct sockaddr *addr, int fd);

#endif /* __HEV_SOCKS5_SESSION_TCP_H__ */
