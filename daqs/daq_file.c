/*--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
/* daq_file.c author Russ Combs <rucombs@cisco.com> */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "daq_user.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>

#include <daq_api.h>
#include <sfbpf_dlt.h>

#define DAQ_MOD_VERSION 0
#define DAQ_NAME "file"
#define DAQ_TYPE (DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_MULTI_INSTANCE)
#define FILE_BUF_SZ 16384

typedef struct {
    char* name;
    int fid;

    int start;
    int stop;
    int eof;

    unsigned snaplen;

    uint8_t* buf;
    char error[DAQ_ERRBUF_SIZE];

    DAQ_UsrHdr_t pci;
    DAQ_State state;
    DAQ_Stats_t stats;
} FileImpl;

//-------------------------------------------------------------------------
// file functions
//-------------------------------------------------------------------------

static int file_setup(FileImpl* impl)
{
    if ( !strcmp(impl->name, "tty") )
    {
        impl->fid = STDIN_FILENO;
    }
    else if ( (impl->fid = open(impl->name, O_RDONLY|O_NONBLOCK)) < 0 )
    {
        DPE(impl->error, "%s: can't open file (%s)\n",
            DAQ_NAME, strerror(errno));
        return -1;
    }
    impl->start = 1;

    return 0;
}

static void file_cleanup(FileImpl* impl)
{
    if ( impl->fid > STDIN_FILENO )
        close(impl->fid);

    impl->fid = -1;
}

static int file_read(FileImpl* impl)
{
    int n = read(impl->fid, impl->buf, impl->snaplen);

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

    if ( impl->start )
    {
        impl->pci.flags = DAQ_USR_FLAG_START_FLOW;
        impl->start = 0;
    }
    else if ( impl->eof )
        impl->pci.flags = DAQ_USR_FLAG_END_FLOW;

    else
        impl->pci.flags = 0;

    phdr->priv_ptr = &impl->pci;
}

static int file_daq_process(
    FileImpl* impl, DAQ_Analysis_Func_t cb, void* user)
{
    DAQ_PktHdr_t hdr;
    int n = file_read(impl);

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

static void file_daq_shutdown (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;

    if ( impl->name )
        free(impl->name);

    if ( impl->buf )
        free(impl->buf);

    free(impl);
}

//-------------------------------------------------------------------------

static int file_daq_initialize (
    const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
    FileImpl* impl = calloc(1, sizeof(*impl));

    if ( !impl )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw context", DAQ_NAME);
        return DAQ_ERROR_NOMEM;
    }

    impl->fid = -1;
    impl->start = impl->stop = 0;
    impl->snaplen = cfg->snaplen ? cfg->snaplen : FILE_BUF_SZ;

    if ( cfg->name )
    {
        if ( !(impl->name = strdup(cfg->name)) )
        {
            snprintf(errBuf, errMax, "%s: failed to allocate the filename", DAQ_NAME);
            free(impl);
            return DAQ_ERROR_NOMEM;
        }
    }

    if ( !(impl->buf = malloc(impl->snaplen)) )
    {
        snprintf(errBuf, errMax, "%s: failed to allocate the ipfw buffer", DAQ_NAME);
        file_daq_shutdown(impl);
        return DAQ_ERROR_NOMEM;
    }

    impl->state = DAQ_STATE_INITIALIZED;

    *handle = impl;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int file_daq_start (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;

    if ( file_setup(impl) )
        return DAQ_ERROR;

    impl->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

static int file_daq_stop (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    file_cleanup(impl);
    impl->state = DAQ_STATE_STOPPED;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int file_daq_inject (
    void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* buf, uint32_t len,
    int rev)
{
    (void)handle;
    (void)hdr;
    (void)buf;
    (void)len;
    (void)rev;
    return DAQ_ERROR;
}

//-------------------------------------------------------------------------

static int file_daq_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t meta, void* user)
{
    (void)meta;

    FileImpl* impl = (FileImpl*)handle;
    int hit = 0, miss = 0;
    impl->stop = 0;

    while ( (hit < cnt || cnt <= 0) && !impl->stop )
    {
        int status = file_daq_process(impl, callback, user);

        if ( status > 0 )
        {
            hit++;
            miss = 0;
        }
        else if ( status < 0 )
            return status;

        else if ( ++miss == 2 )
            break;
    }
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int file_daq_breakloop (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    impl->stop = 1;
    return DAQ_SUCCESS;
}

static DAQ_State file_daq_check_status (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->state;
}

static int file_daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    FileImpl* impl = (FileImpl*)handle;
    *stats = impl->stats;
    return DAQ_SUCCESS;
}

static void file_daq_reset_stats (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    memset(&impl->stats, 0, sizeof(impl->stats));
}

static int file_daq_get_snaplen (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->snaplen;
}

static uint32_t file_daq_get_capabilities (void* handle)
{
    (void)handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START;
}

static int file_daq_get_datalink_type(void *handle)
{
    (void)handle;
    return DLT_USER;
}

static const char* file_daq_get_errbuf (void* handle)
{
    FileImpl* impl = (FileImpl*)handle;
    return impl->error;
}

static void file_daq_set_errbuf (void* handle, const char* s)
{
    FileImpl* impl = (FileImpl*)handle;
    DPE(impl->error, "%s", s ? s : "");
}

static int file_daq_get_device_index(void* handle, const char* device)
{
    (void)handle;
    (void)device;
    return DAQ_ERROR_NOTSUP;
}

static int file_daq_set_filter (void* handle, const char* filter)
{
    (void)handle;
    (void)filter;
    return DAQ_ERROR_NOTSUP;
}

static int file_query_flow(void* handle, const DAQ_PktHdr_t* hdr, DAQ_QueryFlow_t* query)
{
    FileImpl* impl = (FileImpl*)handle;

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

#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_Module_t DAQ_MODULE_DATA =
#else
DAQ_Module_t file_daq_module_data =
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_MOD_VERSION,
    .name = DAQ_NAME,
    .type = DAQ_TYPE,
    .initialize = file_daq_initialize,
    .set_filter = file_daq_set_filter,
    .start = file_daq_start,
    .acquire = file_daq_acquire,
    .inject = file_daq_inject,
    .breakloop = file_daq_breakloop,
    .stop = file_daq_stop,
    .shutdown = file_daq_shutdown,
    .check_status = file_daq_check_status,
    .get_stats = file_daq_get_stats,
    .reset_stats = file_daq_reset_stats,
    .get_snaplen = file_daq_get_snaplen,
    .get_capabilities = file_daq_get_capabilities,
    .get_datalink_type = file_daq_get_datalink_type,
    .get_errbuf = file_daq_get_errbuf,
    .set_errbuf = file_daq_set_errbuf,
    .get_device_index = file_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
    .dp_add_dc = NULL,
    .query_flow = file_query_flow
};

