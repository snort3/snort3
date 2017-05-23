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

#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "daq.h"
#include "daq_api.h"

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
}DAQRegTestContext;

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
    if ( fgets(config->buf , size, fh) == NULL )
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

//-------------------------------------------------------------------------

static int daq_regtest_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t meta, void* user)
{
    DAQRegTestContext* context = (DAQRegTestContext*)handle;
    return context->module->acquire(context->handle, cnt, callback, meta, user);
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
    return context->module->get_capabilities(context->handle);
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
    .modify_flow = NULL,
    .hup_prep = daq_regtest_hup_prep,
    .hup_apply = daq_regtest_hup_apply,
    .hup_post = daq_regtest_hup_post,
};
