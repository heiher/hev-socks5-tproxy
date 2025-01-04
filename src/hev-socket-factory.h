/*
 ============================================================================
 Name        : hev-socket-factory.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Socket Factory
 ============================================================================
 */

#ifndef __HEV_SOCKET_FACTORY_H__
#define __HEV_SOCKET_FACTORY_H__

int hev_socket_factory_get (const char *addr, const char *port, int type,
                            int force_reuseport);

#endif /* __HEV_SOCKET_FACTORY_H__ */
