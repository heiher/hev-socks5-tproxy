/*
 ============================================================================
 Name        : hev-tsocks-cache.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 hev
 Description : Transparent Socket Cache
 ============================================================================
 */

#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-list.h"
#include "hev-rbtree.h"
#include "hev-logger.h"
#include "hev-compiler.h"
#include "hev-config-const.h"

#include "hev-tsocks-cache.h"

typedef struct _HevTSock HevTSock;

struct _HevTSock
{
    HevListNode lnode;
    HevRBTreeNode rnode;

    struct sockaddr_in6 addr;
    int fd;
};

static int cached;
static HevList lru;
static HevRBTree cache;
static pthread_rwlock_t rwlock;
static pthread_spinlock_t spinlock;

int
hev_tsocks_cache_init (void)
{
    int res;

    LOG_D ("tsocks cache init");

    cached = 0;
    memset (&lru, 0, sizeof (lru));
    memset (&cache, 0, sizeof (cache));

    res = pthread_rwlock_init (&rwlock, NULL);
    if (res < 0) {
        LOG_E ("tsocks rwlock init");
        return -1;
    }

    res = pthread_spin_init (&spinlock, PTHREAD_PROCESS_PRIVATE);
    if (res < 0) {
        LOG_E ("tsocks spinlock init");
        return -1;
    }

    return 0;
}

static HevTSock *
hev_tsocks_cache_tsock_new (struct sockaddr *addr)
{
    HevTSock *self;
    int addrlen;
    int one = 1;
    int res;
    int fd;

    addrlen = sizeof (struct sockaddr_in6);

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0)
        goto close;

    res = setsockopt (fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof (one));
    if (res < 0)
        goto close;

    res = bind (fd, addr, addrlen);
    if (res < 0)
        goto close;

    self = hev_malloc0 (sizeof (HevTSock));
    if (res < 0)
        goto close;

    LOG_D ("%p tsocks cache tsock new", self);

    self->fd = fd;
    memcpy (&self->addr, addr, addrlen);

    return self;

close:
    close (fd);
    return NULL;
}

static void
hev_tsocks_cache_tsock_destroy (HevTSock *self)
{
    LOG_D ("%p tsocks cache tsock destroy", self);

    close (self->fd);
    hev_free (self);
}

void
hev_tsocks_cache_fini (void)
{
    HevListNode *node;

    LOG_D ("tsocks cache fini");

    node = hev_list_first (&lru);
    while (node) {
        HevTSock *ts;

        ts = container_of (node, HevTSock, lnode);
        node = hev_list_node_next (node);
        hev_tsocks_cache_tsock_destroy (ts);
    }

    pthread_rwlock_destroy (&rwlock);
    pthread_spin_destroy (&spinlock);
}

static HevTSock *
hev_tsocks_cache_find (struct sockaddr *addr)
{
    HevRBTreeNode *node = cache.root;

    while (node) {
        HevTSock *this;
        int res;

        this = container_of (node, HevTSock, rnode);
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

static int
hev_tsocks_cache_add (HevTSock *ts)
{
    HevRBTreeNode **new = &cache.root, *parent = NULL;

    while (*new) {
        HevTSock *this;
        int res;

        this = container_of (*new, HevTSock, rnode);
        res = memcmp (&this->addr, &ts->addr, sizeof (struct sockaddr_in6));

        parent = *new;
        if (res < 0)
            new = &((*new)->left);
        else if (res > 0)
            new = &((*new)->right);
        else
            return -1;
    }

    cached++;
    hev_list_add_tail (&lru, &ts->lnode);
    hev_rbtree_node_link (&ts->rnode, parent, new);
    hev_rbtree_insert_color (&cache, &ts->rnode);

    return 0;
}

static void
hev_tsocks_cache_del (HevTSock *ts)
{
    cached--;
    hev_list_del (&lru, &ts->lnode);
    hev_rbtree_erase (&cache, &ts->rnode);
}

static void
hev_tsocks_cache_update (HevTSock *ts)
{
    hev_list_del (&lru, &ts->lnode);
    hev_list_add_tail (&lru, &ts->lnode);
}

int
hev_tsocks_cache_get (struct sockaddr *addr)
{
    for (;;) {
        HevTSock *ts;
        int res;

        pthread_rwlock_rdlock (&rwlock);
        ts = hev_tsocks_cache_find (addr);
        if (ts) {
            pthread_spin_lock (&spinlock);
            hev_tsocks_cache_update (ts);
            pthread_spin_unlock (&spinlock);
            return ts->fd;
        }
        pthread_rwlock_unlock (&rwlock);

        if (cached >= TSOCKS_MAX_CACHED) {
            pthread_rwlock_wrlock (&rwlock);
            if (cached >= TSOCKS_MAX_CACHED) {
                HevListNode *node;
                node = hev_list_first (&lru);
                ts = container_of (node, HevTSock, lnode);
                hev_tsocks_cache_del (ts);
            }
            pthread_rwlock_unlock (&rwlock);
            if (ts)
                hev_tsocks_cache_tsock_destroy (ts);
        }

        ts = hev_tsocks_cache_tsock_new (addr);
        if (!ts)
            break;

        pthread_rwlock_wrlock (&rwlock);
        res = hev_tsocks_cache_add (ts);
        pthread_rwlock_unlock (&rwlock);
        if (res < 0)
            hev_tsocks_cache_tsock_destroy (ts);
    }

    return -1;
}

void
hev_tsocks_cache_put (int fd)
{
    pthread_rwlock_unlock (&rwlock);
}
