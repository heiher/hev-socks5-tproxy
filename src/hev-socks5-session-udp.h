/*
 ============================================================================
 Name        : hev-socks5-session-udp.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Socks5 Session UDP
 ============================================================================
 */

#ifndef __HEV_SOCKS5_SESSION_UDP_H__
#define __HEV_SOCKS5_SESSION_UDP_H__

#include <netinet/in.h>

#include "hev-list.h"
#include "hev-rbtree.h"

#include "hev-socks5-session.h"

#define HEV_SOCKS5_SESSION_UDP(p) ((HevSocks5SessionUDP *)p)
#define HEV_SOCKS5_SESSION_UDP_CLASS(p) ((HevSocks5SessionUDPClass *)p)

typedef struct _HevSocks5SessionUDP HevSocks5SessionUDP;
typedef struct _HevSocks5SessionUDPClass HevSocks5SessionUDPClass;

struct _HevSocks5SessionUDP
{
    HevSocks5Session base;

    HevList frame_list;
    HevRBTreeNode node;
    struct sockaddr_in6 addr;
    int frames;
};

struct _HevSocks5SessionUDPClass
{
    HevSocks5SessionClass base;
};

int hev_socks5_session_udp_construct (HevSocks5SessionUDP *self);
void hev_socks5_session_udp_destruct (HevSocks5Session *base);

HevSocks5SessionUDP *hev_socks5_session_udp_new (struct sockaddr *addr);

int hev_socks5_session_udp_send (HevSocks5SessionUDP *self, void *data,
                                 size_t len, struct sockaddr *addr);

#endif /* __HEV_SOCKS5_SESSION_UDP_H__ */
