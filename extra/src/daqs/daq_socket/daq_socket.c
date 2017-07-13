/*--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
*/
/* daq_socket.c author Russ Combs <rucombs@cisco.com> */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>

#include <daq_api.h>
#include <sfbpf_dlt.h>

#include <daqs/daq_user.h>

#define DAQ_MOD_VERSION 0
#define DAQ_NAME "socket"
#define DAQ_TYPE (DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE)
#define DEFAULT_PORT 8000

typedef struct {
    int sock_a;  // recv from b
    int sock_b;  // recv from a
    int sock_c;  // connect

    int use_a;
    int port;
    int passive;
    int stop;

    unsigned timeout;
    unsigned snaplen;

    struct sockaddr_in sin_a;
    struct sockaddr_in sin_b;

    DAQ_UsrHdr_t pci;

    uint8_t* buf;
    char error[DAQ_ERRBUF_SIZE];

    DAQ_State state;
    DAQ_Stats_t stats;
} SockImpl;

//-------------------------------------------------------------------------
// socket functions
//-------------------------------------------------------------------------

static int sock_setup(SockImpl* impl)
{
    struct sockaddr_in sin;

    if ( (impl->sock_c = socket(PF_INET, SOCK_STREAM, 0)) == -1 )
    {
        DPE(impl->error, "%s: can't create listener socket (%s)\n", __func__, strerror(errno));
        return -1;
    }

    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(impl->port);

    if ( bind(impl->sock_c, (struct sockaddr*)&sin, sizeof(sin)) == -1 )
    {
        DPE(impl->error, "%s: can't bind listener socket (%s)\n", __func__, strerror(errno));
        return -1;
    }

    if ( listen(impl->sock_c, 2) == -1 )
    {
        DPE(impl->error, "%s: can't listen on socket (%s)\n", __func__, strerror(errno));
        return -1;
    }
    return 0;
}

static void sock_cleanup(SockImpl* impl)
{
    if ( impl->sock_c >= 0 )
        close(impl->sock_c);

    if ( impl->sock_a >= 0 )
        close(impl->sock_a);

    if ( impl->sock_b >= 0 )
        close(impl->sock_b);

    impl->sock_c = impl->sock_a = impl->sock_b = -1;
}

static int sock_recv(SockImpl* impl, int* sock)
{
    int n = recv(*sock, impl->buf, impl->snaplen, 0);

    if ( n <= 0 )
    {
        if (errno != EINTR)
        {
            DPE(impl->error, "%s: can't recv from socket (%s)\n", __func__, strerror(errno));
            impl->pci.flags = DAQ_USR_FLAG_END_FLOW;
            *sock = -1;
        }
        return 0;
    }
    return n;
}

static int sock_send(
    SockImpl* impl, int sock, const uint8_t* buf, uint32_t len)
{
    if ( sock < 0 )
        return 0;

    int n = send(sock, buf, len, 0);

    while ( 0 <= n && (uint32_t)n < len )
    {
        buf += n;
        len -= n;
        n = send(sock, buf, len, 0);
    }
    if ( n == -1 )
    {
        DPE(impl->error, "%s: can't send on socket (%s)\n", __func__, strerror(errno));
        return -1;
    }
    return 0;
}

static int sock_accept(SockImpl* impl, int* sock, struct sockaddr_in* psin)
{
    const char* banner;
    socklen_t len = sizeof(*psin);
    *sock = accept(impl->sock_c, (struct sockaddr*)psin, &len);

    if ( *sock == -1 )
    {
        DPE(impl->error, "%s: can't accept incoming connection (%s)\n", __func__, strerror(errno));
        return -1;
    }
    banner = impl->use_a ? "client\n" : "server\n";
    sock_send(impl, *sock, (const uint8_t*)banner, 7);

    impl->pci.flags = DAQ_USR_FLAG_START_FLOW;
    return 0;
}

static int sock_poll(SockImpl* impl, int* sock, struct sockaddr_in* psin)
{
    int max_fd;
    fd_set inputs;

    if ( impl->sock_c < 0 )
        return 0;

    FD_ZERO(&inputs);
    FD_SET(impl->sock_c, &inputs);
    max_fd = impl->sock_c;

    if ( *sock > 0 )
    {
        FD_SET(*sock, &inputs);

        if ( *sock > max_fd )
            max_fd = *sock;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if ( !select(max_fd+1, &inputs, NULL, NULL, &timeout) )
        return 0;

    else if ( *sock >= 0 && FD_ISSET(*sock, &inputs) )
        return sock_recv(impl, sock);

    else if ( *sock < 0 && FD_ISSET(impl->sock_c, &inputs) )
        return sock_accept(impl, sock, psin);

    return 0;
}

//-------------------------------------------------------------------------
// daq utilities
//-------------------------------------------------------------------------

static void clear(SockImpl* impl)
{
    if ( impl->sock_a < 0 )
    {
        impl->sin_a.sin_addr.s_addr = 0;
        impl->sin_a.sin_port = 0;
    }
    if ( impl->sock_b < 0 )
    {
        impl->sin_b.sin_addr.s_addr = 0;
        impl->sin_b.sin_port = 0;
    }
}

static void set_pkt_hdr(SockImpl* impl, DAQ_PktHdr_t* phdr, ssize_t len)
{
    struct timeval t;
    gettimeofday(&t, NULL);

    phdr->ts.tv_sec = t.tv_sec;
    phdr->ts.tv_usec = t.tv_usec;
    phdr->caplen = len;
    phdr->pktlen = len;
    phdr->ingress_index = -1;
    phdr->egress_index = -1;
    phdr->ingress_group = -1;
    phdr->egress_group = -1;
    phdr->flags = 0;
    phdr->address_space_id = 0;
    phdr->opaque = 0;

    // use_a already toggled
    if ( impl->use_a )
    {
        impl->pci.src_addr = impl->sin_b.sin_addr.s_addr;
        impl->pci.dst_addr = impl->sin_a.sin_addr.s_addr;
        impl->pci.src_port = impl->sin_b.sin_port;
        impl->pci.dst_port = impl->sin_a.sin_port;
        impl->pci.flags &= ~DAQ_USR_FLAG_TO_SERVER;
    }
    else
    {
        impl->pci.src_addr = impl->sin_a.sin_addr.s_addr;
        impl->pci.dst_addr = impl->sin_b.sin_addr.s_addr;
        impl->pci.src_port = impl->sin_a.sin_port;
        impl->pci.dst_port = impl->sin_b.sin_port;
        impl->pci.flags |= DAQ_USR_FLAG_TO_SERVER;
    }

    if ( impl->pci.flags & DAQ_USR_FLAG_END_FLOW )
        clear(impl);

    phdr->priv_ptr = &impl->pci;
}

// forward all but drops, retries and blacklists:
static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1, 0 };

static int socket_daq_process(
    SockImpl* impl, DAQ_Analysis_Func_t cb, void* user)
{
    DAQ_PktHdr_t hdr;
    int* sock = impl->use_a ? &impl->sock_a : &impl->sock_b;
    struct sockaddr_in* psin = impl->use_a ? &impl->sin_a : &impl->sin_b;
    impl->pci.flags = 0;

    int n = sock_poll(impl, sock, psin);

    // don't toggle w/o at least one connection so client is always 1st
    if ( impl->sock_a > -1 || impl->sock_b > -1 )
        impl->use_a = !impl->use_a;

    if ( n <= 0 && !impl->pci.flags )
        return n;

    set_pkt_hdr(impl, &hdr, n);
    DAQ_Verdict verdict = cb(user, &hdr, impl->buf);

    if ( verdict >= MAX_DAQ_VERDICT )
        verdict = DAQ_VERDICT_BLOCK;

    impl->stats.verdicts[verdict]++;

    if ( impl->passive || s_fwd[verdict] )
    {
        // already toggled use_a, so we get a->b or b->a
        sock = impl->use_a ? &impl->sock_a : &impl->sock_b;
        sock_send(impl, *sock, impl->buf, n);
    }
    return n;
}

static int socket_daq_config (
    SockImpl* impl, const DAQ_Config_t* cfg, char* errBuf, size_t errMax)
{
    DAQ_Dict* entry;

    if ( cfg->name )
    {
        char* end = NULL;
        impl->port = (int)strtol(cfg->name, &end, 0);
    }
    for ( entry = cfg->values; entry; entry = entry->next)
    {
        if ( !entry->value || !*entry->value )
        {
            snprintf(errBuf, errMax, "%s: variable needs value (%s)\n", __func__, entry->key);
            return DAQ_ERROR;
        }
        else if ( !strcmp(entry->key, "port") )
        {
            char* end = entry->value;
            impl->port = (int)strtol(entry->value, &end, 0);

            if ( *end || impl->port <= 0 || impl->port > 65535 )
            {
                snprintf(errBuf, errMax, "%s: bad port (%s)\n", __func__, entry->value);
                return DAQ_ERROR;
            }
        }
        else if ( !strcmp(entry->key, "proto") )
        {
            if ( !strcmp(entry->value, "tcp") )
                impl->pci.ip_proto = IPPROTO_TCP;

            else if ( !strcmp(entry->value, "udp") )
                impl->pci.ip_proto = IPPROTO_UDP;
            else
            {
                snprintf(errBuf, errMax, "%s: bad proto (%s)\n", __func__, entry->value);
                return DAQ_ERROR;
            }
        }
        else
        {
            snprintf(errBuf, errMax,
                "%s: unsupported variable (%s=%s)\n", __func__, entry->key, entry->value);
            return DAQ_ERROR;
        }
    }
    if ( !impl->pci.ip_proto )
        impl->pci.ip_proto = IPPROTO_TCP;

    if ( !impl->port )
        impl->port = DEFAULT_PORT;

    impl->snaplen = cfg->snaplen ? cfg->snaplen : IP_MAXPACKET;
    impl->timeout = cfg->timeout;
    impl->passive = ( cfg->mode == DAQ_MODE_PASSIVE );

    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static void socket_daq_shutdown (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;

    if ( impl->buf )
        free(impl->buf);

    free(impl);
}

//-------------------------------------------------------------------------

static int socket_daq_initialize (
    const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
    SockImpl* impl = calloc(1, sizeof(*impl));

    if ( !impl )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw context!", __func__);
        return DAQ_ERROR_NOMEM;
    }

    if ( socket_daq_config(impl, cfg, errBuf, errMax) != DAQ_SUCCESS )
    {
        socket_daq_shutdown(impl);
        return DAQ_ERROR;
    }
    impl->buf = malloc(impl->snaplen);

    if ( !impl->buf )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw buffer!", __func__);
        socket_daq_shutdown(impl);
        return DAQ_ERROR_NOMEM;
    }

    impl->sock_c = impl->sock_a = impl->sock_b = -1;
    impl->use_a = 1;
    impl->state = DAQ_STATE_INITIALIZED;

    *handle = impl;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int socket_daq_start (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;

    if ( sock_setup(impl) )
        return DAQ_ERROR;

    impl->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

static int socket_daq_stop (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    sock_cleanup(impl);
    impl->state = DAQ_STATE_STOPPED;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int socket_daq_inject (
    void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* buf, uint32_t len,
    int reverse)
{
    (void)hdr;

    SockImpl* impl = (SockImpl*)handle;
    int sock;

    if ( reverse )
        sock = impl->use_a ? impl->sock_b : impl->sock_a;
    else
        sock = impl->use_a ? impl->sock_a : impl->sock_b;

    int status = sock_send(impl, sock, buf, len);

    if ( status )
        return DAQ_ERROR;

    impl->stats.packets_injected++;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int socket_daq_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t meta, void* user)
{
    (void)meta;

    SockImpl* impl = (SockImpl*)handle;
    int hit = 0, miss = 0;
    impl->stop = 0;

    while ( hit < cnt || cnt <= 0 )
    {
        int status = socket_daq_process(impl, callback, user);

        if ( status > 0 )
        {
            hit++;
            miss = 0;
        }
        else if ( status < 0 )
            return DAQ_ERROR;

        else if ( ++miss == 2 || impl->stop )
            break;
    }
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int socket_daq_breakloop (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    impl->stop = 1;
    return DAQ_SUCCESS;
}

static DAQ_State socket_daq_check_status (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    return impl->state;
}

static int socket_daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    SockImpl* impl = (SockImpl*)handle;
    *stats = impl->stats;
    return DAQ_SUCCESS;
}

static void socket_daq_reset_stats (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    memset(&impl->stats, 0, sizeof(impl->stats));
}

static int socket_daq_get_snaplen (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    return impl->snaplen;
}

static uint32_t socket_daq_get_capabilities (void* handle)
{
    (void)handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START;
}

static int socket_daq_get_datalink_type(void *handle)
{
    (void)handle;
    return DLT_USER;
}

static const char* socket_daq_get_errbuf (void* handle)
{
    SockImpl* impl = (SockImpl*)handle;
    return impl->error;
}

static void socket_daq_set_errbuf (void* handle, const char* s)
{
    SockImpl* impl = (SockImpl*)handle;
    DPE(impl->error, "%s", s ? s : "");
}

static int socket_daq_get_device_index(void* handle, const char* device)
{
    (void)handle;
    (void)device;
    return DAQ_ERROR_NOTSUP;
}

static int socket_daq_set_filter (void* handle, const char* filter)
{
    (void)handle;
    (void)filter;
    return DAQ_ERROR_NOTSUP;
}

static int socket_query_flow(void* handle, const DAQ_PktHdr_t* hdr, DAQ_QueryFlow_t* query)
{
    SockImpl* impl = (SockImpl*)handle;

    if ( hdr->priv_ptr != &impl->pci )  // sanity check
        return DAQ_ERROR_INVAL;

    if ( query->type == DAQ_USR_QUERY_PCI )
    {
        query->value = &impl->pci;
        query->length = sizeof(impl->pci);
        return DAQ_SUCCESS;
    }
    return DAQ_ERROR_NOTSUP;
}

//-------------------------------------------------------------------------

DAQ_SO_PUBLIC DAQ_Module_t DAQ_MODULE_DATA =
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_MOD_VERSION,
    .name = DAQ_NAME,
    .type = DAQ_TYPE,
    .initialize = socket_daq_initialize,
    .set_filter = socket_daq_set_filter,
    .start = socket_daq_start,
    .acquire = socket_daq_acquire,
    .inject = socket_daq_inject,
    .breakloop = socket_daq_breakloop,
    .stop = socket_daq_stop,
    .shutdown = socket_daq_shutdown,
    .check_status = socket_daq_check_status,
    .get_stats = socket_daq_get_stats,
    .reset_stats = socket_daq_reset_stats,
    .get_snaplen = socket_daq_get_snaplen,
    .get_capabilities = socket_daq_get_capabilities,
    .get_datalink_type = socket_daq_get_datalink_type,
    .get_errbuf = socket_daq_get_errbuf,
    .set_errbuf = socket_daq_set_errbuf,
    .get_device_index = socket_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
    .dp_add_dc = NULL,
    .query_flow = socket_query_flow
};
