/*
 * ftp_telnet.c
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 * Kevin Liu <kliu@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Description:
 *
 * This file initializes FTPTelnet as a Snort preprocessor.
 *
 * This file registers the FTPTelnet initialization function,
 * adds the FTPTelnet function into the preprocessor list, reads
 * the user configuration in the snort.conf file, and prints out
 * the configuration that is read.
 *
 * In general, this file is a wrapper to FTPTelnet functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of FTPTelnet should be separate from the preprocessor hooks.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "snort_types.h"
#include "snort_debug.h"

#include "ftpp_si.h"
#include "ftpp_ui_config.h"
#include "ft_main.h"
#include "profiler.h"
#include "stream5/stream_api.h"
#include "file_api/file_api.h"
#include "parser.h"
#include "framework/inspector.h"

/* FIXTHIS even static preprocs need version
 * so that a dynamic one can override a la daq
 */
#if 0
const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 2;
const int BUILD_VERSION = 13;
const char *PREPROC_NAME = "SF_FTPTELNET";

#define SetupFTPTelnet DYNAMIC_PREPROC_SETUP
#endif

int16_t ftp_app_id = SFTARGET_UNKNOWN_PROTOCOL;
int16_t ftp_data_app_id = SFTARGET_UNKNOWN_PROTOCOL;
int16_t telnet_app_id = SFTARGET_UNKNOWN_PROTOCOL;

#ifdef PERF_PROFILING
THREAD_LOCAL PreprocStats ftpPerfStats;
THREAD_LOCAL PreprocStats telnetPerfStats;
static THREAD_LOCAL PreprocStats ftpdataPerfStats;

static PreprocStats* ft_get_profile(const char* key)
{
    if ( !strcmp(key, "ftptelnet_ftp") )
        return &ftpPerfStats;

    if ( !strcmp(key, "ftptelnet_telnet") )
        return &telnetPerfStats;

    if ( !strcmp(key, "ftptelnet_ftpdata") )
        return &ftpdataPerfStats;

    return nullptr;
}
#endif

static THREAD_LOCAL SimpleStats ftstats;
static SimpleStats gftstats;

THREAD_LOCAL FTPTELNET_GLOBAL_CONF* ftp_telnet_config = NULL;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class FtpTelnet : public Inspector {
public:
    FtpTelnet();
    ~FtpTelnet();

    void configure(SnortConfig*, const char*, char *args);
    int verify(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);
    void eval_alt(Packet*);

private:
    FTPTELNET_GLOBAL_CONF* config;
};

FtpTelnet::FtpTelnet()
{
    config = (FTPTELNET_GLOBAL_CONF*)calloc(1, sizeof(*config));
}

FtpTelnet::~FtpTelnet ()
{
    FTPTelnetFreeConfig(config);
}

void FtpTelnet::configure (
    SnortConfig* sc, const char*, char *args){
    FtpTelnetConfig(sc, config, args);
}

int FtpTelnet::verify(SnortConfig* sc)
{
    return FTPTelnetCheckConfigs(sc, config);
}

void FtpTelnet::show(SnortConfig*)
{
    PrintFtpTelnetConfig(config);
}

void FtpTelnet::eval_alt(Packet* p)
{
    // precondition - what we registered for
    assert(IsTCP(p) && p->data && p->dsize);

    SnortFTPTelnet(config, p);
}

void FtpTelnet::eval(Packet* p)
{
    ftp_telnet_config = config; // FIXIT change to use "config" data member

    // precondition - what we registered for
    assert(IsTCP(p));

    if ( file_api->get_max_file_depth() >= 0 )
    {
        if ( stream.get_application_protocol_id(p->flow)
            == ftp_data_app_id )
        {
            PROFILE_VARS;
            PREPROC_PROFILE_START(ftpdataPerfStats);
            ++ftstats.total_packets;
            SnortFTPData(p);
            PREPROC_PROFILE_END(ftpdataPerfStats);
            return;
        }
    }
    if ( !p->dsize || (p->data == NULL) )
        return;

    ++ftstats.total_packets;
    SnortFTPTelnet(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static const char* name = "ftp_telnet";

static void ft_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "ftptelnet_ftp", &ftpPerfStats, 0, &totalPerfStats, ft_get_profile);
    RegisterPreprocessorProfile(
        "ftptelnet_telnet", &telnetPerfStats, 0, &totalPerfStats, ft_get_profile);
    RegisterPreprocessorProfile(
        "ftptelnet_ftpdata", &ftpdataPerfStats, 0, &totalPerfStats, ft_get_profile);
#endif

    ftp_app_id = AddProtocolReference("ftp");
    ftp_data_app_id = AddProtocolReference("ftp-data");
    telnet_app_id = AddProtocolReference("telnet");

    // FIXIT telnet must go first
    // ftp and ftp-data use telnet's flow_id; 
    TelnetFlowData::init();
    FtpFlowData::init();
    FtpDataFlowData::init();
}

static Inspector* ft_ctor(Module*)
{
    return new FtpTelnet;
}

static void ft_dtor(Inspector* p)
{
    delete p;
}

static void ft_sum(void*)
{
    sum_stats(&gftstats, &ftstats);
}

static void ft_stats(void*)
{
    show_stats(&gftstats, name);
}

static void ft_reset(void*)
{
    memset(&gftstats, 0, sizeof(gftstats));
}

static const InspectApi ft_api =
{
    {
        PT_INSPECTOR,
        name,
        INSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    PRIORITY_SESSION, // or PRIORITY_APPLICATION
    PROTO_BIT__TCP,
    ft_init,
    nullptr, // term
    ft_ctor,
    ft_dtor,
    nullptr, // stop
    nullptr, // purge
    ft_sum,
    ft_stats,
    ft_reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ft_api.base,
    nullptr
};
#else
const BaseApi* sin_ftp_telnet = &ft_api.base;
#endif

