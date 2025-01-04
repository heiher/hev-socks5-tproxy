/*
 ============================================================================
 Name        : hev-socks5-worker.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : Socks5 Worker
 ============================================================================
 */

#ifndef __HEV_SOCKS5_WORKER_H__
#define __HEV_SOCKS5_WORKER_H__

typedef struct _HevSocks5Worker HevSocks5Worker;

HevSocks5Worker *hev_socks5_worker_new (void);
void hev_socks5_worker_destroy (HevSocks5Worker *self);
int hev_socks5_worker_init (HevSocks5Worker *self, int is_main);

void hev_socks5_worker_start (HevSocks5Worker *self);
void hev_socks5_worker_stop (HevSocks5Worker *self);

#endif /* __HEV_SOCKS5_WORKER_H__ */
