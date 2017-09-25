/*--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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
/* daq_regtest.c author Bhagya Tholpady <bbantwal@cisco.com> */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq.h>
#include <daq_api.h>
#include <stdlib.h>
#include <string.h>

#define DAQ_MOD_VERSION 0
#define DAQ_NAME "regtest"
#define DAQ_TYPE (DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | \
                          DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE)
#define REGTEST_DEBUG_FILE "daq_regtest_debug"
#define REGTEST_CONFIG_FILE "daq_regtest.conf"

typedef struct
{
    char* buf;
    int config_num;
}DAQRegTestConfig;

typedef struct
{
    DAQRegTestConfig* daq_regtest_cfg;
    FILE* debug_fh;
    int daq_config_reads;
    const DAQ_Module_t* module;
    void *handle;
    int skip;
    int trace;
    DAQ_PktHdr_t retry_hdr;
    uint8_t* retry_data;
    unsigned packets_before_retry;
    unsigned retry_packet_countdown;
    void* user;
    DAQ_Analysis_Func_t wrapped_packet_callback;
}DAQRegTestContext;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

// packet tracer configuration from command line daq-var skip and trace
// --daq-var skip=10 --daq-var trace=5 would trace packets 11 through 15 only
static void daq_regtest_get_vars(DAQRegTestContext* context, const DAQ_Config_t* cfg)
{
    DAQ_Dict* entry;

    context->skip = 0;
    context->trace = 0;
    context->packets_before_retry = 0;

    for ( entry = cfg->values; entry; entry = entry->next)
    {
        if ( !strcmp(entry->key, "skip") )
        {
            context->skip = atoi(entry->value);
        }
        else if ( !strcmp(entry->key, "trace") )
        {
            context->trace = atoi(entry->value);
        }
        else if ( !strcmp(entry->key, "packets_before_retry") )
        {
            context->packets_before_retry = atoi(entry->value);
        }
    }
}

static int daq_regtest_parse_config(DAQRegTestContext *context, DAQRegTestConfig** new_config, char* errBuf, size_t errMax)
{
    long size = 0;
    FILE* fh = fopen(REGTEST_CONFIG_FILE, "r");

    if (!fh)
    {
        if ( errBuf )
            snprintf(errBuf, errMax, "%s: failed to open the daq_regtest config file", DAQ_NAME);
        return DAQ_ERROR;
    }
    DAQRegTestConfig* config = calloc(1, sizeof(DAQRegTestConfig));
    if ( !config )
    {
        if ( errBuf )
            snprintf(errBuf, errMax, "%s: failed to allocate daq_regtest config", DAQ_NAME);
        fclose(fh);
        return DAQ_ERROR_NOMEM;
    }

    fseek(fh, 0, SEEK_END);
    size = ftell(fh);
    config->buf = (char*) calloc(size, sizeof(char));
    if ( !config->buf )
    {
        if ( errBuf )
            snprintf(errBuf, errMax, "%s: failed to allocate daq_regtest buffer", DAQ_NAME);
        free(config);
        fclose(fh);
        return DAQ_ERROR_NOMEM;
    }
    rewind(fh);
    if ( fgets(config->buf, size, fh) == NULL )
    {
        if ( errBuf )
            snprintf(errBuf, errMax, "%s: failed to read daq_regtest config file", DAQ_NAME);
        free(config);
        fclose(fh);
        return DAQ_ERROR;
    }
    context->daq_config_reads++;
    config->config_num = context->daq_config_reads;
    *new_config = config;
    fclose(fh);

    return DAQ_SUCCESS;
}

static int daq_regtest_init_context(DAQRegTestContext* context, char* errBuf, size_t errMax)
{
    context->debug_fh = NULL;
    return daq_regtest_parse_config(context, &(context->daq_regtest_cfg), errBuf, errMax);
}
static void daq_regtest_cleanup(DAQRegTestContext* context)
{
    context->module = NULL;
    context->handle = NULL;

    if ( context->debug_fh )
        fclose(context->debug_fh);

    if ( context->daq_regtest_cfg )
    {
        if ( context->daq_regtest_cfg->buf )
            free(context->daq_regtest_cfg->buf);
        free(context->daq_regtest_cfg);
    }

    free(context);
}

//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static void daq_regtest_shutdown (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;

    if (context->debug_fh)
        fprintf (context->debug_fh, "daq_regtest shutdown\n");

    context->module->shutdown(context->handle);
    daq_regtest_cleanup(context);
}

static void daq_regtest_debug(DAQRegTestContext* context, char* msg)
{
    if (context->debug_fh)
    {
        fprintf (context->debug_fh, "%s\n", msg);
        fprintf (context->debug_fh, "daq_regtest config : \n\tbuf = %s \n\tconfig_num = %d \n", 
                context->daq_regtest_cfg->buf, context->daq_regtest_cfg->config_num);
        fflush(context->debug_fh);
    }
}

//-------------------------------------------------------------------------

static int daq_regtest_initialize (
    const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
    DAQRegTestContext* context;
    int rval = DAQ_SUCCESS;

    context = calloc(1, sizeof(*context));
    if ( !context )
    {
        snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the new daq_regtest context!", DAQ_NAME);
        return DAQ_ERROR_NOMEM;
    }

    rval = daq_regtest_init_context(context, errBuf, errMax);

    if ( rval != DAQ_SUCCESS )
    {
        free(context);
        return rval;
    }

    daq_regtest_get_vars(context, cfg);

    context->module = daq_find_module("dump");

    if (!context->module)
    {
        snprintf(errBuf, errMax, "%s: Can't find dump daq required by daq_regtest module!", DAQ_NAME);
        daq_regtest_cleanup(context);
        return DAQ_ERROR;
    }

    context->debug_fh = fopen(REGTEST_DEBUG_FILE, "w");

    rval = context->module->initialize(cfg, &context->handle, errBuf, errMax);
    if ( rval != DAQ_SUCCESS )
    {
        daq_regtest_cleanup(context);
        return rval;
    }
    daq_regtest_debug(context, "daq_regtest initialized");
    *handle = context;
    return rval;
}

//-------------------------------------------------------------------------

static int daq_regtest_start (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->start(context->handle);
}

static int daq_regtest_stop (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->stop(context->handle);
}

//-------------------------------------------------------------------------

static int daq_regtest_inject (
    void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* buf, uint32_t len,
    int reverse)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->inject(context->handle, hdr, buf, len, reverse);
}

static DAQ_Verdict daq_handle_retry_request(DAQRegTestContext* context, const DAQ_PktHdr_t* hdr,
    const uint8_t* data)
{
    // FIXIT-L for current reg test needs or snort only 1 pending retry is required so if we
    //         get a 2nd request we just let it pass.  future support for >1 pending retries
    //         can be implemented with a list holding the hdr & data for each retry packet.
    if ( !context->retry_data )
    {
        context->retry_hdr = *hdr;
        context->retry_data = malloc(hdr->caplen);
        if ( context->retry_data )
        {
            memcpy(context->retry_data, data, hdr->caplen);
            context->retry_packet_countdown = context->packets_before_retry;
            return DAQ_VERDICT_BLOCK;
        }
    }

    return DAQ_VERDICT_PASS;
}

static void daq_handle_pending_retry(DAQRegTestContext* context)
{
    if ( !context->retry_packet_countdown )
    {
        context->retry_hdr.flags |= DAQ_PKT_FLAG_RETRY_PACKET;
        DAQ_Verdict verdict = context->wrapped_packet_callback(context->user,
            &context->retry_hdr, context->retry_data);

        if (verdict >= MAX_DAQ_VERDICT)
            verdict = DAQ_VERDICT_PASS;
        verdict = verdict_translation_table[verdict];
        if ( verdict == DAQ_VERDICT_PASS )
            context->module->inject(context->handle, &context->retry_hdr, context->retry_data,
                context->retry_hdr.pktlen, 0);
        free(context->retry_data);
        context->retry_data = NULL;
    }
    else
        context->retry_packet_countdown--;
}

//-------------------------------------------------------------------------
static DAQ_Verdict daq_regtest_packet_callback(void* user, const DAQ_PktHdr_t* hdr,
    const uint8_t* data)
{
    DAQRegTestContext* context = (DAQRegTestContext*)user;

    if ( context->skip == 0 && context->trace > 0 )
    {
        DAQ_PktHdr_t* pkthdr = (DAQ_PktHdr_t*)hdr;
        pkthdr->flags |= DAQ_PKT_FLAG_TRACE_ENABLED;
    }

    if ( context->skip > 0 )
        context->skip--;
    else if ( context->trace > 0 )
        context->trace--;

    if ( context->retry_data )
        daq_handle_pending_retry(context);

    DAQ_Verdict verdict = context->wrapped_packet_callback(context->user,
        hdr, data);
    if ( verdict == DAQ_VERDICT_RETRY )
        verdict = daq_handle_retry_request(context, hdr, data);

    return verdict;
}

static int daq_regtest_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t meta, void* user)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    context->wrapped_packet_callback = callback;
    context->user = user;
    context->retry_data = NULL;

    return context->module->acquire(context->handle, cnt, daq_regtest_packet_callback, meta, handle);
}

//-------------------------------------------------------------------------

static int daq_regtest_breakloop (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->breakloop(context->handle);
}

static DAQ_State daq_regtest_check_status (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->check_status(context->handle);
}

static int daq_regtest_get_stats (void* handle, DAQ_Stats_t* stats)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->get_stats(context->handle, stats);
}

static void daq_regtest_reset_stats (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    context->module->reset_stats(context->handle);
}

static int daq_regtest_get_snaplen (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->get_snaplen(context->handle);
}

static uint32_t daq_regtest_get_capabilities (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    uint32_t caps = context->module->get_capabilities(context->handle);
    caps |= DAQ_CAPA_RETRY;
    return caps;
}

static int daq_regtest_get_datalink_type(void *handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->get_datalink_type(context->handle);
}

static const char* daq_regtest_get_errbuf (void* handle)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->get_errbuf(context->handle);
}

static void daq_regtest_set_errbuf (void* handle, const char* s)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    context->module->set_errbuf(context->handle, s);
}

static int daq_regtest_get_device_index(void* handle, const char* device)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->get_device_index(context->handle, device);
}

static int daq_regtest_modify_flow(void *handle, const DAQ_PktHdr_t *hdr, const DAQ_ModFlow_t *modify)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;

    if (modify->type == DAQ_MODFLOW_TYPE_PKT_TRACE)
    {
        if (modify->length != sizeof(DAQ_ModFlowPktTrace_t))
            return DAQ_ERROR_INVAL;

        DAQ_ModFlowPktTrace_t* mod_tr = (DAQ_ModFlowPktTrace_t *) modify->value;
        printf("DAQ_REGTEST_PKT_TRACE (%d)\n%s\n", mod_tr->pkt_trace_data_len,
            mod_tr->pkt_trace_data);
    }
    if (context->module->modify_flow)
        return context->module->modify_flow(context->handle, hdr, modify);
    else
        return DAQ_SUCCESS;
}

static int daq_regtest_set_filter (void* handle, const char* filter)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->set_filter(context->handle, filter);
}

static int daq_regtest_hup_prep(void *handle, void **new_config)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    DAQRegTestConfig* newConf;
    int rval = DAQ_SUCCESS;

    if ( ( rval = daq_regtest_parse_config(context, &newConf, NULL, 0) ) == DAQ_SUCCESS )
    {
        daq_regtest_debug(context, "daq_regtest hup_prep succeeded");
        *new_config = newConf;
    }
    else
        daq_regtest_debug(context, "daq_regtest hup_prep failed");
    return rval;
}

static int daq_regtest_hup_apply(void *handle, void *new_config, void **old_config)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    DAQRegTestConfig* config = (DAQRegTestConfig*)new_config;

    *old_config = context->daq_regtest_cfg;
    context->daq_regtest_cfg = config;
    daq_regtest_debug(context, "daq_regtest hup_apply succeeded");

    return DAQ_SUCCESS;
}

static int daq_regtest_hup_post(void *handle, void *old_config)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    DAQRegTestConfig* config = (DAQRegTestConfig*)old_config;

    daq_regtest_debug(context, "daq_regtest hup_post succeeded");

    if ( config->buf ) 
        free(config->buf);
    free(config);

    return DAQ_SUCCESS;
}


//-------------------------------------------------------------------------

DAQ_SO_PUBLIC DAQ_Module_t DAQ_MODULE_DATA =
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_MOD_VERSION,
    .name = DAQ_NAME,
    .type = DAQ_TYPE,
    .initialize = daq_regtest_initialize,
    .set_filter = daq_regtest_set_filter,
    .start = daq_regtest_start,
    .acquire = daq_regtest_acquire,
    .inject = daq_regtest_inject,
    .breakloop = daq_regtest_breakloop,
    .stop = daq_regtest_stop,
    .shutdown = daq_regtest_shutdown,
    .check_status = daq_regtest_check_status,
    .get_stats = daq_regtest_get_stats,
    .reset_stats = daq_regtest_reset_stats,
    .get_snaplen = daq_regtest_get_snaplen,
    .get_capabilities = daq_regtest_get_capabilities,
    .get_datalink_type = daq_regtest_get_datalink_type,
    .get_errbuf = daq_regtest_get_errbuf,
    .set_errbuf = daq_regtest_set_errbuf,
    .get_device_index = daq_regtest_get_device_index,
    .modify_flow = daq_regtest_modify_flow,
    .hup_prep = daq_regtest_hup_prep,
    .hup_apply = daq_regtest_hup_apply,
    .hup_post = daq_regtest_hup_post,
};
