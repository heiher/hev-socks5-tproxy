/*
 ============================================================================
 Name        : hev-tsocks-cache.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2026 hev
 Description : Transparent Socket Cache
 ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-logger.h"
#include "hev-config-const.h"

#include "hev-tsocks-cache.h"

#define TABLE_BITS (7)
#define TABLE_SIZE (1 << TABLE_BITS)
#define TABLE_MASK (TABLE_SIZE - 1)
#define SLOT_FREE (1u << 31)

_Static_assert (TSOCKS_MAX_CACHED <= 255,
                "table entries index slots by a byte");
_Static_assert (TSOCKS_MAX_CACHED * 2 <= TABLE_SIZE, "table load factor");

typedef struct _HevTSockSlot HevTSockSlot;

struct _HevTSockSlot
{
    HevTSock ts;
} __attribute__ ((aligned (64)));

static HevTSockSlot slots[TSOCKS_MAX_CACHED];

/* Each entry is (tag << 8 | slot + 1), or 0 when it is empty. */
static _Atomic uint16_t table[TABLE_SIZE] __attribute__ ((aligned (64)));

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int hand;

int
hev_tsocks_cache_init (void)
{
    int i;

    LOG_D ("tsocks cache init");

    hand = 0;
    for (i = 0; i < TABLE_SIZE; i++)
        atomic_init (&table[i], 0);
    for (i = 0; i < TSOCKS_MAX_CACHED; i++)
        atomic_init (&slots[i].ts.refs, SLOT_FREE);

    return 0;
}

void
hev_tsocks_cache_fini (void)
{
    int i;

    LOG_D ("tsocks cache fini");

    for (i = 0; i < TSOCKS_MAX_CACHED; i++) {
        HevTSock *ts = &slots[i].ts;

        if (!(atomic_load_explicit (&ts->refs, memory_order_acquire) &
              SLOT_FREE))
            close (ts->fd);
        atomic_store_explicit (&ts->refs, SLOT_FREE, memory_order_relaxed);
    }
}

static uint32_t
hev_tsocks_cache_hash (const struct in6_addr *addr, in_port_t port)
{
    uint32_t words[4];
    uint32_t hash = port;
    int i;

    memcpy (words, addr, sizeof (words));

    for (i = 0; i < 4; i++) {
        hash = (hash ^ words[i]) * 0x9e3779b1u;
        hash ^= hash >> 15;
    }

    return hash * 0x9e3779b1u;
}

/*
 * Only the fields bind() depends on identify a socket. The kernel ignores the
 * scope of an address that doesn't need one, and the flow info altogether, and
 * callers don't always initialize them.
 */
static uint32_t
hev_tsocks_cache_scope (const struct sockaddr_in6 *addr)
{
    const struct in6_addr *ip = &addr->sin6_addr;

    if (IN6_IS_ADDR_LINKLOCAL (ip) || IN6_IS_ADDR_MC_LINKLOCAL (ip) ||
        IN6_IS_ADDR_MC_NODELOCAL (ip))
        return addr->sin6_scope_id;

    return 0;
}

static HevTSock *
hev_tsocks_cache_find (const struct sockaddr_in6 *addr, uint32_t scope,
                       uint32_t hash)
{
    unsigned int pos = hash >> (32 - TABLE_BITS);
    unsigned int tag = hash & 0xff;
    int i;

    for (i = 0; i < TABLE_SIZE; i++, pos = (pos + 1) & TABLE_MASK) {
        unsigned int entry;
        HevTSock *ts;

        entry = atomic_load_explicit (&table[pos], memory_order_relaxed);
        if (!entry)
            break;
        if ((entry >> 8) != tag)
            continue;

        ts = &slots[(entry & 0xff) - 1].ts;

        if (atomic_fetch_add_explicit (&ts->refs, 1, memory_order_acquire) &
            SLOT_FREE) {
            atomic_fetch_sub_explicit (&ts->refs, 1, memory_order_relaxed);
            continue;
        }

        if (ts->port != addr->sin6_port || ts->scope != scope ||
            memcmp (&ts->addr, &addr->sin6_addr, sizeof (ts->addr))) {
            atomic_fetch_sub_explicit (&ts->refs, 1, memory_order_release);
            continue;
        }

        if (!atomic_load_explicit (&ts->used, memory_order_relaxed))
            atomic_store_explicit (&ts->used, 1, memory_order_relaxed);

        return ts;
    }

    return NULL;
}

static void
hev_tsocks_cache_table_add (HevTSock *ts, int slot)
{
    unsigned int pos = ts->hash >> (32 - TABLE_BITS);

    while (atomic_load_explicit (&table[pos], memory_order_relaxed))
        pos = (pos + 1) & TABLE_MASK;

    atomic_store_explicit (&table[pos], (ts->hash & 0xff) << 8 | (slot + 1),
                           memory_order_relaxed);
}

static void
hev_tsocks_cache_table_del (HevTSock *ts, int slot)
{
    unsigned int pos = ts->hash >> (32 - TABLE_BITS);
    unsigned int i;

    while ((atomic_load_explicit (&table[pos], memory_order_relaxed) & 0xff) !=
           slot + 1)
        pos = (pos + 1) & TABLE_MASK;

    /* Close the gap, so that the entries after it can still be probed. */
    for (i = pos;;) {
        unsigned int entry;
        unsigned int home;

        i = (i + 1) & TABLE_MASK;
        entry = atomic_load_explicit (&table[i], memory_order_relaxed);
        if (!entry)
            break;

        home = slots[(entry & 0xff) - 1].ts.hash >> (32 - TABLE_BITS);
        if (((i - home) & TABLE_MASK) >= ((i - pos) & TABLE_MASK)) {
            atomic_store_explicit (&table[pos], entry, memory_order_relaxed);
            pos = i;
        }
    }

    atomic_store_explicit (&table[pos], 0, memory_order_relaxed);
}

/*
 * Claim a free slot or evict one without pins that wasn't used recently, using
 * the clock algorithm. Returns the slot, or -1 when every slot is pinned, and
 * the fd the caller must close once it has released the mutex, or -1.
 */
static int
hev_tsocks_cache_claim (int *fd)
{
    int i;

    *fd = -1;

    for (i = 0; i < TSOCKS_MAX_CACHED * 2; i++) {
        unsigned int slot = hand;
        unsigned int refs = 1;
        HevTSock *ts = &slots[slot].ts;

        hand = (hand + 1) % TSOCKS_MAX_CACHED;

        if (atomic_load_explicit (&ts->refs, memory_order_relaxed) & SLOT_FREE)
            return slot;

        if (atomic_load_explicit (&ts->used, memory_order_relaxed)) {
            atomic_store_explicit (&ts->used, 0, memory_order_relaxed);
            continue;
        }

        if (atomic_compare_exchange_strong_explicit (
                &ts->refs, &refs, SLOT_FREE, memory_order_acquire,
                memory_order_relaxed)) {
            hev_tsocks_cache_table_del (ts, slot);
            *fd = ts->fd;
            return slot;
        }
    }

    return -1;
}

static int
hev_tsocks_cache_socket (const struct sockaddr_in6 *addr, uint32_t scope)
{
    struct sockaddr_in6 saddr = {
        .sin6_family = AF_INET6,
        .sin6_port = addr->sin6_port,
        .sin6_addr = addr->sin6_addr,
        .sin6_scope_id = scope,
    };
    int one = 1;
    int res;
    int fd;

    fd = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0)
        goto close;

    res = setsockopt (fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof (one));
    if (res < 0)
        goto close;

    res = bind (fd, (struct sockaddr *)&saddr, sizeof (saddr));
    if (res < 0)
        goto close;

    return fd;

close:
    close (fd);
    return -1;
}

/*
 * Every slot is pinned by a task that yielded while sending. This is the only
 * case with more than TSOCKS_MAX_CACHED sockets, and it lasts until the put.
 */
static HevTSock *
hev_tsocks_cache_transient (int fd)
{
    HevTSock *ts;

    ts = hev_malloc0 (sizeof (HevTSock));
    if (!ts) {
        close (fd);
        return NULL;
    }

    LOG_D ("%p tsocks cache transient tsock", ts);

    ts->transient = 1;
    ts->fd = fd;

    return ts;
}

static HevTSock *
hev_tsocks_cache_add (const struct sockaddr_in6 *addr, uint32_t scope,
                      uint32_t hash)
{
    HevTSock *ts;
    int old_fd;
    int slot;
    int fd;

    pthread_mutex_lock (&mutex);
    ts = hev_tsocks_cache_find (addr, scope, hash);
    pthread_mutex_unlock (&mutex);
    if (ts)
        return ts;

    /* Create first, an address that can't be bound must not evict others. */
    fd = hev_tsocks_cache_socket (addr, scope);
    if (fd < 0 && (errno == EMFILE || errno == ENFILE)) {
        pthread_mutex_lock (&mutex);
        hev_tsocks_cache_claim (&old_fd);
        pthread_mutex_unlock (&mutex);
        if (old_fd >= 0)
            close (old_fd);
        fd = hev_tsocks_cache_socket (addr, scope);
    }
    if (fd < 0)
        return NULL;

    pthread_mutex_lock (&mutex);

    /* Another worker may have added it while the socket was being created. */
    ts = hev_tsocks_cache_find (addr, scope, hash);
    if (ts) {
        pthread_mutex_unlock (&mutex);
        close (fd);
        return ts;
    }

    slot = hev_tsocks_cache_claim (&old_fd);
    if (slot < 0) {
        pthread_mutex_unlock (&mutex);
        return hev_tsocks_cache_transient (fd);
    }

    ts = &slots[slot].ts;
    ts->addr = addr->sin6_addr;
    ts->port = addr->sin6_port;
    ts->scope = scope;
    ts->hash = hash;
    ts->fd = fd;
    ts->transient = 0;
    atomic_store_explicit (&ts->used, 0, memory_order_relaxed);

    hev_tsocks_cache_table_add (ts, slot);

    /* Publish with the reference of the cache and the one of the caller, and
     * subtract to preserve any add of a reader that is about to undo it. */
    atomic_fetch_sub_explicit (&ts->refs, SLOT_FREE - 2, memory_order_release);

    pthread_mutex_unlock (&mutex);

    if (old_fd >= 0)
        close (old_fd);

    LOG_D ("%p tsocks cache tsock new", ts);

    return ts;
}

HevTSock *
hev_tsocks_cache_get (struct sockaddr *addr)
{
    const struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;
    uint32_t scope = hev_tsocks_cache_scope (saddr);
    uint32_t hash;
    HevTSock *ts;

    hash = hev_tsocks_cache_hash (&saddr->sin6_addr, saddr->sin6_port);

    ts = hev_tsocks_cache_find (saddr, scope, hash);
    if (ts)
        return ts;

    return hev_tsocks_cache_add (saddr, scope, hash);
}

void
hev_tsocks_cache_put (HevTSock *ts)
{
    if (ts->transient) {
        close (ts->fd);
        hev_free (ts);
        return;
    }

    /* Pairs with the claim, the fd is closed only after its users are done. */
    atomic_fetch_sub_explicit (&ts->refs, 1, memory_order_release);
}
