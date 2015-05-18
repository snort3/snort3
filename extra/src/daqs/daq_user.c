/*--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
/* daq_user.c author Russ Combs <rucombs@cisco.com> */

#include "daq_socket.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>

#include <daq_api.h>
#include <sfbpf_dlt.h>

#define DAQ_MOD_VERSION 0
#define DAQ_NAME "user"
#define DAQ_TYPE (DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_MULTI_INSTANCE)

#define DEF_BUF_SZ 16384
#define MAX_LINE_SZ  128

typedef struct {
    char* name;
    FILE* fyle;

    int start;
    int stop;
    int eof;
    int fsm;

    unsigned snaplen;
    unsigned idx;

    uint8_t* buf;
    char line[MAX_LINE_SZ];
    char error[DAQ_ERRBUF_SIZE];

    DAQ_SktHdr_t pci;
    DAQ_SktHdr_t cfg;

    DAQ_State state;
    DAQ_Stats_t stats;
} FileImpl;

//-------------------------------------------------------------------------
// utility functions
//-------------------------------------------------------------------------

static void set_c2s(FileImpl* impl, int c2s)
{
    if ( c2s )
    {
        impl->pci = impl->cfg;
    }
    else
    {
        impl->pci.src_addr = impl->cfg.dst_addr;
        impl->pci.dst_addr = impl->cfg.src_addr;
        impl->pci.src_port = impl->cfg.dst_port;
        impl->pci.dst_port = impl->cfg.src_port;
        impl->pci.flags &= ~DAQ_SKT_FLAG_TO_SERVER;
    }
}

static void parse_host(const char* s, uint32_t* addr, uint16_t* port)
{
    char buf[32];  // oversize so pton() errors out if too long
    unsigned c = 0;

    while ( isspace(*s) )
        s++;

    while ( *s && !isspace(*s) && c < sizeof(buf) )
        buf[c++] = *s++;

    if ( c == sizeof(buf) )
        --c;

    buf[c] = '\0';

    inet_pton(AF_INET, buf, addr);
    *port = atoi(s);
}

static void parse_pci(FileImpl* impl, const char* s)
{
    parse_host(s, &impl->pci.src_addr, &impl->pci.src_port);

    s = strstr(s, "->");

    if ( !s )
        return;

    parse_host(s+2, &impl->pci.dst_addr, &impl->pci.dst_port);

    // hack until client / server is resolved:
    if ( impl->pci.src_port >= impl->pci.dst_port )
        impl->pci.flags |= DAQ_SKT_FLAG_TO_SERVER;
    else
        impl->pci.flags &= ~DAQ_SKT_FLAG_TO_SERVER;
}

static unsigned flush(FileImpl* impl)
{
    unsigned n = impl->idx;
    impl->idx = 0;
    return n;
}

static uint8_t xlat(char c)
{
    switch ( c )
    {
    case 'r': return '\r';
    case 'n': return '\n';
    case 't': return '\t';
    case '\\': return '\\';
    }
    return c;
}

static int unescape(char c, char* u)
{
    static int esc = 0;
    if ( !esc && c == '\\' )
    {
        esc = 1;
        return 0;
    }
    else if ( esc )
    {
        esc = 0;
        *u = xlat(c);
    }
    else
        *u = c;

    return 1;
}

//-------------------------------------------------------------------------
// parsing functions
//-------------------------------------------------------------------------
// all commands start with $
// $packet <addr> <port> -> <addr> <port>
// $packet -> client
// $packet -> server
// $client <addr> <port>
// $server <addr> <port>
static void parse_command(FileImpl* impl, char* s)
{
    if ( !strncmp(s, "packet -> client", 16) )
        set_c2s(impl, 0);

    else if ( !strncmp(s, "packet -> server", 16) )
        set_c2s(impl, 1);

    else if ( !strncmp(s, "packet ", 7) )
        parse_pci(impl, s+7);

    else if ( !strncmp(s, "client ", 7) )
        parse_host(s+7, &impl->cfg.src_addr, &impl->cfg.src_port);

    else if ( !strncmp(s, "server ", 7) )
        parse_host(s+7, &impl->cfg.dst_addr, &impl->cfg.dst_port);
}

// load quoted string data into buffer up to snaplen
static void parse_string(FileImpl* impl, char* s)
{
    char t;

    while ( *s && *s != '"' && impl->idx < impl->snaplen )
    {
        if ( unescape(*s++, &t) )
            impl->buf[impl->idx++] = t;
    }
}

// load hex data into buffer up to snaplen
static void parse_hex(FileImpl* impl, char* s)
{
    char* t = s;
    long x = strtol(t, &s, 16);

    while ( *s && s != t && impl->idx < impl->snaplen )
    {
        impl->buf[impl->idx++] = (uint8_t)x;
        x = strtol(t=s, &s, 16);
    }
}

static int parse(FileImpl* impl)
{
    char* s = impl->line;

    while ( isspace(*s) )
        s++;

    switch ( *s )
    {
    case '\0':
        impl->line[0] = '\0';
        return flush(impl);

    case '#':
        break;

    case '$':
        if ( impl->idx )
            return flush(impl);

        parse_command(impl, s+1);
        break;

    case '"':
        parse_string(impl, s+1);
        break;

    case 'x':
        parse_hex(impl, s+1);
        break;
    }
    impl->line[0] = '\0';
    return 0;
}

//-------------------------------------------------------------------------
// file functions
//-------------------------------------------------------------------------

static int user_setup(FileImpl* impl)
{
    if ( !strcmp(impl->name, "tty") )
    {
        impl->fyle = stdin;
    }
    else if ( !(impl->fyle = fopen(impl->name, "r")) )
    {
        DPE(impl->error, "%s: can't open file (%s)\n",
            DAQ_NAME, strerror(errno));
        return -1;
    }
    parse_host("192.168.1.1 12345", &impl->cfg.src_addr, &impl->cfg.src_port);
    parse_host("10.1.2.3 80", &impl->cfg.dst_addr, &impl->cfg.dst_port);

    impl->cfg.ip_proto = impl->pci.ip_proto = IPPROTO_TCP;
    impl->cfg.flags = impl->pci.flags = DAQ_SKT_FLAG_TO_SERVER;
    impl->start = 1;

    return 0;
}

static void user_cleanup(FileImpl* impl)
{
    if ( impl->fyle != stdin )
        fclose(impl->fyle);

    impl->fyle = NULL;
}

static int user_read(FileImpl* impl)
{
    int n = 0;

    while ( impl->line[0] || fgets(impl->line, sizeof(impl->line), impl->fyle) )
    {
        if ( (n = parse(impl)) )
            break;
    }

    if ( !n )
        n = flush(impl);

    if ( !n )
    {
        if ( !impl->eof )
        {
            impl->eof = 1;
            return 1;  // <= zero won't make it :(
        }
        return DAQ_READFILE_EOF;
    }

    if ( n < 0 )
    {
        if (errno != EINTR)
        {
            DPE(impl->error, "%s: can't read from file (%s)\n",
                DAQ_NAME, strerror(errno));
        }
        return DAQ_ERROR;
    }
    return n;
}

//-------------------------------------------------------------------------
// daq utilities
//-------------------------------------------------------------------------

static void set_pkt_hdr(FileImpl* impl, DAQ_PktHdr_t* phdr, ssize_t len)
{
    struct timeval t;
    gettimeofday(&t, NULL);

    phdr->ts.tv_sec = t.tv_sec;
    phdr->ts.tv_usec = t.tv_usec;
    phdr->caplen = phdr->pktlen = len;

    phdr->ingress_index = phdr->egress_index = -1;
    phdr->ingress_group = phdr->egress_group = -1;

    phdr->flags = 0;
    phdr->address_space_id = 0;
    phdr->opaque = 0;

    impl->pci.flags &= ~(DAQ_SKT_FLAG_START_FLOW|DAQ_SKT_FLAG_END_FLOW);

    if ( impl->start )
    {
        impl->pci.flags |= DAQ_SKT_FLAG_START_FLOW;
        impl->start = 0;
    }
    else if ( impl->eof )
        impl->pci.flags |= DAQ_SKT_FLAG_END_FLOW;

    phdr->priv_ptr = &impl->pci;
}

// forward all but drops, retries and blacklists:
static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1, 0 };

static int user_daq_process(
    FileImpl* impl, DAQ_Analysis_Func_t cb, void* user)
{
    DAQ_PktHdr_t hdr;
    int n = user_read(impl);

    if ( n < 1 )
        return n;

    set_pkt_hdr(impl, &hdr, n);
    DAQ_Verdict verdict = cb(user, &hdr, impl->buf);

    if ( verdict >= MAX_DAQ_VERDICT )
        verdict = DAQ_VERDICT_BLOCK;

    impl->stats.verdicts[verdict]++;
    return n;
}

//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static void user_daq_shutdown (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;

    if ( impl->name )
        free(impl->name);

    if ( impl->buf )
        free(impl->buf);

    free(impl);
}

//-------------------------------------------------------------------------

static int user_daq_initialize (
    const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
    FileImpl* impl = calloc(1, sizeof(*impl));

    if ( !impl )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw context", DAQ_NAME);
        return DAQ_ERROR_NOMEM;
    }

    impl->fyle = NULL;
    impl->start = impl->stop = 0;
    impl->snaplen = cfg->snaplen ? cfg->snaplen : DEF_BUF_SZ;

    impl->idx = 0;
    impl->fsm = 0;
    impl->line[0] = '\0';

    if ( cfg->name )
    {
        if ( !(impl->name = strdup(cfg->name)) )
        {
            snprintf(errBuf, errMax, "%s: failed to allocate the filename", DAQ_NAME);
            return DAQ_ERROR_NOMEM;
        }
    }

    if ( !(impl->buf = malloc(impl->snaplen)) )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw buffer", DAQ_NAME);
        user_daq_shutdown(impl);
        return DAQ_ERROR_NOMEM;
    }

    impl->state = DAQ_STATE_INITIALIZED;

    *handle = impl;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int user_daq_start (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;

    if ( user_setup(impl) )
        return DAQ_ERROR;

    impl->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

static int user_daq_stop (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    user_cleanup(impl);
    impl->state = DAQ_STATE_STOPPED;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int user_daq_inject (
    void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* buf, uint32_t len, int rev)
{
    (void)handle;
    (void)hdr;
    (void)buf;
    (void)len;
    (void)rev;
    return DAQ_ERROR;
}

//-------------------------------------------------------------------------

static int user_daq_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t meta, void* user)
{
    (void)meta;

    FileImpl* impl = (FileImpl*)handle;
    int hit = 0, miss = 0;
    impl->stop = 0;

    while ( hit < cnt || cnt <= 0 )
    {
        int status = user_daq_process(impl, callback, user);

        if ( status > 0 )
        {
            hit++;
            miss = 0;
        }
        else if ( status < 0 )
            return status;

        else if ( ++miss == 2 || impl->stop )
            break;
    }
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int user_daq_breakloop (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    impl->stop = 1;
    return DAQ_SUCCESS;
}

static DAQ_State user_daq_check_status (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->state;
}

static int user_daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    FileImpl* impl = (FileImpl*)handle;
    *stats = impl->stats;
    return DAQ_SUCCESS;
}

static void user_daq_reset_stats (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    memset(&impl->stats, 0, sizeof(impl->stats));
}

static int user_daq_get_snaplen (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->snaplen;
}

static uint32_t user_daq_get_capabilities (void* handle)
{
    (void)handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START;
}

static int user_daq_get_datalink_type(void *handle)
{
    (void)handle;
    return DLT_SOCKET;
}

static const char* user_daq_get_errbuf (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->error;
}

static void user_daq_set_errbuf (void* handle, const char* s)
{
    FileImpl* impl = (FileImpl*)handle;
    DPE(impl->error, "%s", s ? s : "");
}

static int user_daq_get_device_index(void* handle, const char* device)
{
    (void)handle;
    (void)device;
    return DAQ_ERROR_NOTSUP;
}

static int user_daq_set_filter (void* handle, const char* filter)
{
    (void)handle;
    (void)filter;
    return DAQ_ERROR_NOTSUP;
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_Module_t DAQ_MODULE_DATA =
#else
DAQ_Module_t user_daq_module_data =
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_MOD_VERSION,
    .name = DAQ_NAME,
    .type = DAQ_TYPE,
    .initialize = user_daq_initialize,
    .set_filter = user_daq_set_filter,
    .start = user_daq_start,
    .acquire = user_daq_acquire,
    .inject = user_daq_inject,
    .breakloop = user_daq_breakloop,
    .stop = user_daq_stop,
    .shutdown = user_daq_shutdown,
    .check_status = user_daq_check_status,
    .get_stats = user_daq_get_stats,
    .reset_stats = user_daq_reset_stats,
    .get_snaplen = user_daq_get_snaplen,
    .get_capabilities = user_daq_get_capabilities,
    .get_datalink_type = user_daq_get_datalink_type,
    .get_errbuf = user_daq_get_errbuf,
    .set_errbuf = user_daq_set_errbuf,
    .get_device_index = user_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
};

