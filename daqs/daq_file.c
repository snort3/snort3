/*--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <daq_module_api.h>

#define DAQ_MOD_VERSION 0
#define DAQ_NAME "file"
#define DAQ_TYPE (DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_MULTI_INSTANCE)

#define FILE_DEFAULT_POOL_SIZE 16
#define FILE_BUF_SZ 16384

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _file_msg_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    DAQ_UsrHdr_t pci;
    uint8_t* data;
    struct _file_msg_desc* next;
} FileMsgDesc;

typedef struct
{
    FileMsgDesc* pool;
    FileMsgDesc* freelist;
    DAQ_MsgPoolInfo_t info;
} FileMsgPool;

typedef struct
{
    /* Configuration */
    char* filename;
    unsigned snaplen;

    /* State */
    DAQ_ModuleInstance_h modinst;
    FileMsgPool pool;
    int fid;
    volatile bool interrupted;

    bool sof;
    bool eof;

    DAQ_UsrHdr_t pci;
    DAQ_Stats_t stats;
} FileContext;

static DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------
// utility functions
//-------------------------------------------------------------------------

static void destroy_message_pool(FileContext* fc)
{
    FileMsgPool* pool = &fc->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].data);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_message_pool(FileContext* fc, unsigned size)
{
    FileMsgPool* pool = &fc->pool;
    pool->pool = calloc(sizeof(FileMsgDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(fc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(FileMsgDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(FileMsgDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        FileMsgDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(fc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(fc->modinst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, fc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += fc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->owner = fc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// file functions
//-------------------------------------------------------------------------

static int file_setup(FileContext* fc)
{
    if ( !strcmp(fc->filename, "tty") )
    {
        fc->fid = STDIN_FILENO;
    }
    else if ( (fc->fid = open(fc->filename, O_RDONLY|O_NONBLOCK)) < 0 )
    {
        char error_msg[1024] = {0};
        if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
            SET_ERROR(fc->modinst, "%s: can't open file (%s)", DAQ_NAME, error_msg);
        else
            SET_ERROR(fc->modinst, "%s: can't open file: %d", DAQ_NAME, errno);
        return -1;
    }

    fc->sof = true;
    fc->eof = false;

    return 0;
}

static void file_cleanup(FileContext* fc)
{
    if ( fc->fid > STDIN_FILENO )
        close(fc->fid);

    fc->fid = -1;
}

//-------------------------------------------------------------------------
// daq utilities
//-------------------------------------------------------------------------

static void init_packet_message(FileContext* fc, FileMsgDesc* desc)
{
    DAQ_PktHdr_t *pkthdr = &desc->pkthdr;

    desc->msg.type = DAQ_MSG_TYPE_PACKET;
    desc->msg.hdr_len = sizeof(*pkthdr);
    desc->msg.hdr = pkthdr;
    desc->msg.data_len = 0;
    desc->msg.data = desc->data;

    struct timeval t;
    gettimeofday(&t, NULL);

    pkthdr->ts.tv_sec = t.tv_sec;
    pkthdr->ts.tv_usec = t.tv_usec;

    desc->pci = fc->pci;
    if (fc->sof)
    {
        desc->pci.flags |= DAQ_USR_FLAG_START_FLOW;
        fc->sof = false;
    }
}

static DAQ_RecvStatus file_read_message(FileContext* fc, FileMsgDesc* desc)
{
    desc->msg.data = NULL;
    int n = read(fc->fid, desc->data, fc->snaplen);

    if ( n )
    {
        init_packet_message(fc, desc);
        desc->msg.data_len = n;
    }
    else
    {
        // create an empty packet message to convey the End of Flow
        if (!fc->eof)
        {
            init_packet_message(fc, desc);
            desc->pci.flags |= DAQ_USR_FLAG_END_FLOW;
            fc->eof = true;
            return DAQ_RSTAT_EOF;
        }
    }

    if ( n < 0 )
    {
        if (errno != EINTR)
        {
            char error_msg[1024] = {0};
            if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
                SET_ERROR(fc->modinst, "%s: can't read from file (%s)", DAQ_NAME, error_msg);
            else
                SET_ERROR(fc->modinst, "%s: can't read from file: %d", DAQ_NAME, errno);
            return DAQ_RSTAT_ERROR;
        }
    }

    return DAQ_RSTAT_OK;
}

//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static int file_daq_module_load(const DAQ_BaseAPI_t* base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int file_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void** ctxt_ptr)
{
    FileContext* fc;
    int rval = DAQ_ERROR;

    fc = calloc(1, sizeof(*fc));
    if (!fc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new File context!", DAQ_NAME);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    fc->modinst = modinst;

    fc->snaplen = daq_base_api.config_get_snaplen(modcfg) ? daq_base_api.config_get_snaplen(modcfg) : FILE_BUF_SZ;
    fc->fid = -1;

    const char* filename = daq_base_api.config_get_input(modcfg);
    if (filename)
    {
        if (!(fc->filename = strdup(filename)))
        {
            SET_ERROR(modinst, "%s: Couldn't allocate memory for the filename!", DAQ_NAME);
            rval = DAQ_ERROR_NOMEM;
            goto err;
        }
    }

    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    rval = create_message_pool(fc, pool_size ? pool_size : FILE_DEFAULT_POOL_SIZE);
    if (rval != DAQ_SUCCESS)
        goto err;

    *ctxt_ptr = fc;

    return DAQ_SUCCESS;

err:
    if (fc)
    {
        if (fc->filename)
            free(fc->filename);
        destroy_message_pool(fc);
        free(fc);
    }
    return rval;
}

static void file_daq_destroy(void* handle)
{
    FileContext* fc = (FileContext*) handle;

    if (fc->filename)
        free(fc->filename);
    destroy_message_pool(fc);
    free(fc);
}

static int file_daq_start(void* handle)
{
    FileContext* fc = (FileContext*) handle;

    if (file_setup(fc))
        return DAQ_ERROR;

    return DAQ_SUCCESS;
}

static int file_daq_interrupt(void* handle)
{
    FileContext* fc = (FileContext*) handle;
    fc->interrupted = true;
    return DAQ_SUCCESS;
}

static int file_daq_stop (void* handle)
{
    FileContext* fc = (FileContext*) handle;
    file_cleanup(fc);
    return DAQ_SUCCESS;
}

static int file_daq_ioctl(void* handle, DAQ_IoctlCmd cmd, void* arg, size_t arglen)
{
    (void) handle;

    if (cmd == DIOCTL_QUERY_USR_PCI)
    {
        if (arglen != sizeof(DIOCTL_QueryUsrPCI))
            return DAQ_ERROR_INVAL;
        DIOCTL_QueryUsrPCI* qup = (DIOCTL_QueryUsrPCI*) arg;
        if (!qup->msg)
            return DAQ_ERROR_INVAL;
        FileMsgDesc* desc = (FileMsgDesc*) qup->msg->priv;
        qup->pci = &desc->pci;
        return DAQ_SUCCESS;
    }
    return DAQ_ERROR_NOTSUP;
}

static int file_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    FileContext* fc = (FileContext*) handle;
    memcpy(stats, &fc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void file_daq_reset_stats(void* handle)
{
    FileContext* fc = (FileContext*) handle;
    memset(&fc->stats, 0, sizeof(fc->stats));
}

static int file_daq_get_snaplen (void* handle)
{
    FileContext* fc = (FileContext*) handle;
    return fc->snaplen;
}

static uint32_t file_daq_get_capabilities(void* handle)
{
    (void) handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_INTERRUPT | DAQ_CAPA_UNPRIV_START;
}

static int file_daq_get_datalink_type(void *handle)
{
    (void)handle;
    return DLT_USER;
}

static unsigned file_daq_msg_receive(void* handle, const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat)
{
    FileContext* fc = (FileContext*) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    unsigned idx = 0;

    while (idx < max_recv)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (fc->interrupted)
        {
            fc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* Make sure that we have a message descriptor available to populate. */
        FileMsgDesc* desc = fc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        /* Attempt to read a message into the descriptor. */
        status = file_read_message(fc, desc);
        if (status != DAQ_RSTAT_OK)
            break;

        /* Last, but not least, extract this descriptor from the free list and
           place the message in the return vector. */
        fc->pool.freelist = desc->next;
        desc->next = NULL;
        fc->pool.info.available--;
        msgs[idx] = &desc->msg;

        idx++;
    }

    *rstat = status;

    return idx;
}

static int file_daq_msg_finalize(void* handle, const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    FileContext* fc = (FileContext*) handle;
    FileMsgDesc* desc = (FileMsgDesc *) msg->priv;

    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    fc->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = fc->pool.freelist;
    fc->pool.freelist = desc;
    fc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int file_daq_get_msg_pool_info(void* handle, DAQ_MsgPoolInfo_t* info)
{
    FileContext* fc = (FileContext*) handle;

    *info = fc->pool.info;

    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t file_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_MOD_VERSION,
    /* .name = */ DAQ_NAME,
    /* .type = */ DAQ_TYPE,
    /* .load = */ file_daq_module_load,
    /* .unload = */ NULL,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */ file_daq_instantiate,
    /* .destroy = */ file_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ file_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ file_daq_interrupt,
    /* .stop = */ file_daq_stop,
    /* .ioctl = */ file_daq_ioctl,
    /* .get_stats = */ file_daq_get_stats,
    /* .reset_stats = */ file_daq_reset_stats,
    /* .get_snaplen = */ file_daq_get_snaplen,
    /* .get_capabilities = */ file_daq_get_capabilities,
    /* .get_datalink_type = */ file_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ file_daq_msg_receive,
    /* .msg_finalize = */ file_daq_msg_finalize,
    /* .get_msg_pool_info = */ file_daq_get_msg_pool_info,
};

