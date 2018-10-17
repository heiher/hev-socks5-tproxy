/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description : Socks5 session
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>

#include "hev-socks5-session.h"
#include "hev-memory-allocator.h"
#include "hev-task.h"
#include "hev-task-io-socket.h"
#include "hev-config.h"

#define SESSION_HP (10)
#define TASK_STACK_SIZE (3 * 4096)

static void hev_socks5_session_task_entry (void *data);

typedef struct _Socks5AuthHeader Socks5AuthHeader;
typedef struct _Socks5ReqResHeader Socks5ReqResHeader;

enum
{
    STEP_NULL,
    STEP_DO_CONNECT,
    STEP_WRITE_REQUEST,
    STEP_READ_RESPONSE,
    STEP_DO_SPLICE,
    STEP_DO_FWD_DNS,
    STEP_CLOSE_SESSION,
};

struct _HevSocks5Session
{
    HevSocks5SessionBase base;

    int client_fd;
    int remote_fd;
    int ref_count;

    int dns_request_len;
    void *dns_request;
    struct sockaddr_in address;

    HevSocks5SessionCloseNotify notify;
    void *notify_data;
};

struct _Socks5AuthHeader
{
    unsigned char ver;
    union
    {
        unsigned char method;
        unsigned char method_len;
    };
    unsigned char methods[256];
} __attribute__ ((packed));

struct _Socks5ReqResHeader
{
    unsigned char ver;
    union
    {
        unsigned char cmd;
        unsigned char rep;
    };
    unsigned char rsv;
    unsigned char atype;
    union
    {
        struct
        {
            unsigned int addr;
            unsigned short port;
        } ipv4;
        struct
        {
            unsigned char len;
            unsigned char addr[256 + 2];
        } domain;
    };
} __attribute__ ((packed));

static HevSocks5Session *
hev_socks5_session_new (int client_fd, HevSocks5SessionCloseNotify notify,
                        void *notify_data)
{
    HevSocks5Session *self;
    HevTask *task;

    self = hev_malloc0 (sizeof (HevSocks5Session));
    if (!self)
        return NULL;

    self->base.hp = SESSION_HP;

    self->ref_count = 1;
    self->remote_fd = -1;
    self->client_fd = client_fd;
    self->notify = notify;
    self->notify_data = notify_data;

    task = hev_task_new (TASK_STACK_SIZE);
    if (!task) {
        hev_free (self);
        return NULL;
    }

    self->base.task = task;
    hev_task_set_priority (task, 1);

    return self;
}

HevSocks5Session *
hev_socks5_session_new_tcp (int client_fd, HevSocks5SessionCloseNotify notify,
                            void *notify_data)
{
    HevSocks5Session *self;
    struct sockaddr *addr;
    struct sockaddr_in sock_addr;
    socklen_t addr_len;

    self = hev_socks5_session_new (client_fd, notify, notify_data);
    if (!self)
        return NULL;

    /* get socket address */
    addr = (struct sockaddr *)&sock_addr;
    addr_len = sizeof (sock_addr);
    if (getsockname (client_fd, addr, &addr_len) == -1) {
        hev_task_unref (self->base.task);
        hev_free (self);
        return NULL;
    }

    /* get original address */
    addr = (struct sockaddr *)&self->address;
    addr_len = sizeof (self->address);
    if (getsockopt (client_fd, SOL_IP, SO_ORIGINAL_DST, addr, &addr_len) ==
        -1) {
        hev_task_unref (self->base.task);
        hev_free (self);
        return NULL;
    }

    /* check is connect to self */
    if ((sock_addr.sin_port == self->address.sin_port) &&
        (sock_addr.sin_addr.s_addr == self->address.sin_addr.s_addr)) {
        hev_task_unref (self->base.task);
        hev_free (self);
        return NULL;
    }

    return self;
}

HevSocks5Session *
hev_socks5_session_new_dns (int client_fd, HevSocks5SessionCloseNotify notify,
                            void *notify_data)
{
    HevSocks5Session *self;
    struct sockaddr *addr;
    socklen_t addr_len;
    ssize_t s;

    self = hev_socks5_session_new (client_fd, notify, notify_data);
    if (!self)
        return NULL;

    self->dns_request = hev_malloc (2048);
    if (!self->dns_request) {
        hev_task_unref (self->base.task);
        hev_free (self);
        return NULL;
    }

    /* recv dns request */
    addr = (struct sockaddr *)&self->address;
    addr_len = sizeof (self->address);
    s = recvfrom (client_fd, self->dns_request, 2048, 0, addr, &addr_len);
    if (s == -1) {
        hev_free (self->dns_request);
        hev_task_unref (self->base.task);
        hev_free (self);
        return NULL;
    }

#ifdef _DEBUG
    printf ("Receive a DNS message from %s:%u\n",
            inet_ntoa (self->address.sin_addr), ntohs (self->address.sin_port));
#endif
    self->dns_request_len = s;

    return self;
}

HevSocks5Session *
hev_socks5_session_ref (HevSocks5Session *self)
{
    self->ref_count++;

    return self;
}

void
hev_socks5_session_unref (HevSocks5Session *self)
{
    self->ref_count--;
    if (self->ref_count)
        return;

    if (self->dns_request)
        hev_free (self->dns_request);
    hev_free (self);
}

void
hev_socks5_session_run (HevSocks5Session *self)
{
    hev_task_run (self->base.task, hev_socks5_session_task_entry, self);
}

static int
socks5_session_task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5Session *self = data;

    self->base.hp = SESSION_HP;

    hev_task_yield (type);

    return (self->base.hp > 0) ? 0 : -1;
}

static int
socks5_do_connect (HevSocks5Session *self)
{
    HevTask *task;
    int ret, nonblock = 1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (struct sockaddr_in);

    self->remote_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (self->remote_fd == -1)
        return STEP_CLOSE_SESSION;

    ret = ioctl (self->remote_fd, FIONBIO, (char *)&nonblock);
    if (ret == -1)
        return STEP_CLOSE_SESSION;

    task = hev_task_self ();
    hev_task_add_fd (task, self->remote_fd, EPOLLIN | EPOLLOUT);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr (hev_config_get_socks5_address ());
    addr.sin_port = htons (hev_config_get_socks5_port ());

    /* connect */
    ret = hev_task_io_socket_connect (self->remote_fd, (struct sockaddr *)&addr,
                                      addr_len, socks5_session_task_io_yielder,
                                      self);
    if (ret < 0)
        return STEP_CLOSE_SESSION;

    return STEP_WRITE_REQUEST;
}

static int
socks5_write_request (HevSocks5Session *self)
{
    Socks5AuthHeader socks5_auth;
    Socks5ReqResHeader socks5_r;
    ssize_t len;
    struct msghdr mh;
    struct iovec iov[2];

    memset (&mh, 0, sizeof (mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;

    /* write socks5 auth method */
    socks5_auth.ver = 0x05;
    socks5_auth.method_len = 0x01;
    socks5_auth.methods[0] = 0x00;
    iov[0].iov_base = &socks5_auth;
    iov[0].iov_len = 3;

    /* write socks5 request */
    socks5_r.ver = 0x05;
    if (self->dns_request_len)
        socks5_r.cmd = 0x04;
    else
        socks5_r.cmd = 0x01;
    socks5_r.rsv = 0x00;
    socks5_r.atype = 0x01;
    socks5_r.ipv4.addr = self->address.sin_addr.s_addr;
    socks5_r.ipv4.port = self->address.sin_port;
    iov[1].iov_base = &socks5_r;
    iov[1].iov_len = 10;

    len = hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                      socks5_session_task_io_yielder, self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;

    return STEP_READ_RESPONSE;
}

static int
socks5_read_response (HevSocks5Session *self)
{
    Socks5AuthHeader socks5_auth;
    Socks5ReqResHeader socks5_r;
    ssize_t len;

    /* read socks5 auth method */
    len = hev_task_io_socket_recv (self->remote_fd, &socks5_auth, 2,
                                   MSG_WAITALL, socks5_session_task_io_yielder,
                                   self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;
    /* check socks5 version and auth method */
    if (socks5_auth.ver != 0x05 || socks5_auth.method != 0x00)
        return STEP_CLOSE_SESSION;

    /* read socks5 response */
    len = hev_task_io_socket_recv (self->remote_fd, &socks5_r, 10, MSG_WAITALL,
                                   socks5_session_task_io_yielder, self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;
    /* check socks5 version, rep and atype */
    if (socks5_r.ver != 0x05 || socks5_r.rep != 0x00 || socks5_r.atype != 0x01)
        return STEP_CLOSE_SESSION;

    return (self->dns_request_len) ? STEP_DO_FWD_DNS : STEP_DO_SPLICE;
}

static int
socks5_do_splice (HevSocks5Session *self)
{
    hev_task_io_splice (self->client_fd, self->client_fd, self->remote_fd,
                        self->remote_fd, 2048, socks5_session_task_io_yielder,
                        self);

    return STEP_CLOSE_SESSION;
}

static int
socks5_do_fwd_dns (HevSocks5Session *self)
{
    unsigned char buf[2048];
    ssize_t len;
    struct msghdr mh;
    struct iovec iov[2];
    socklen_t addr_len = sizeof (struct sockaddr_in);
    unsigned short dns_len;

    memset (&mh, 0, sizeof (mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;

    /* write dns request length */
    dns_len = htons (self->dns_request_len);
    iov[0].iov_base = &dns_len;
    iov[0].iov_len = 2;

    /* write dns request */
    iov[1].iov_base = self->dns_request;
    iov[1].iov_len = self->dns_request_len;

    /* send dns request */
    len = hev_task_io_socket_sendmsg (self->remote_fd, &mh, MSG_WAITALL,
                                      socks5_session_task_io_yielder, self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;

    /* read dns response length */
    len = hev_task_io_socket_recv (self->remote_fd, &dns_len, 2, MSG_WAITALL,
                                   socks5_session_task_io_yielder, self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;
    dns_len = ntohs (dns_len);

    /* check dns response length */
    if (dns_len >= 2048)
        return STEP_CLOSE_SESSION;

    /* read dns response */
    len = hev_task_io_socket_recv (self->remote_fd, buf, dns_len, MSG_WAITALL,
                                   socks5_session_task_io_yielder, self);
    if (len <= 0)
        return STEP_CLOSE_SESSION;

    /* send dns response */
    hev_task_io_socket_sendto (self->client_fd, buf, len, 0,
                               (struct sockaddr *)&self->address, addr_len,
                               socks5_session_task_io_yielder, self);

    return STEP_CLOSE_SESSION;
}

static int
socks5_close_session (HevSocks5Session *self)
{
    if (self->remote_fd >= 0)
        close (self->remote_fd);
    if (self->dns_request_len == 0)
        close (self->client_fd);

    self->notify (self, self->notify_data);
    hev_socks5_session_unref (self);

    return STEP_NULL;
}

static void
hev_socks5_session_task_entry (void *data)
{
    HevTask *task = hev_task_self ();
    HevSocks5Session *self = data;
    int step = STEP_DO_CONNECT;

    hev_task_add_fd (task, self->client_fd, EPOLLIN | EPOLLOUT);

    while (step) {
        switch (step) {
        case STEP_DO_CONNECT:
            step = socks5_do_connect (self);
            break;
        case STEP_WRITE_REQUEST:
            step = socks5_write_request (self);
            break;
        case STEP_READ_RESPONSE:
            step = socks5_read_response (self);
            break;
        case STEP_DO_SPLICE:
            step = socks5_do_splice (self);
            break;
        case STEP_DO_FWD_DNS:
            step = socks5_do_fwd_dns (self);
            break;
        case STEP_CLOSE_SESSION:
            step = socks5_close_session (self);
            break;
        default:
            step = STEP_NULL;
            break;
        }
    }
}
