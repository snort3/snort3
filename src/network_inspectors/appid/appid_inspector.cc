//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// appid_inspector.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#include "appid_inspector.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler/profiler.h"
#include "fw_appid.h"

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

AppIdInspector::AppIdInspector(const AppIdModuleConfig* pc)
{
    assert(pc);
    config = pc;
}

AppIdInspector::~AppIdInspector()
{
    delete config;
}

bool AppIdInspector::configure(SnortConfig*)
{
    active_config = new AppIdConfig( ( AppIdModuleConfig* )config);
    return active_config->init_appid();

    // FIXIT some of this stuff may be needed in some fashion...
#ifdef REMOVED_WHILE_NOT_IN_USE
    _dpd.registerGeAppId(getOpenAppId);
    if (!thirdparty_appid_module)
        _dpd.streamAPI->register_http_header_callback(httpHeaderCallback);
    _dpd.registerSslAppIdLookup(sslAppGroupIdLookup);

    // FIXIT AppID will need to register for SIP events for sip detection to work...
    if (_dpd.streamAPI->service_event_subscribe(PP_SIP, SIP_EVENT_TYPE_SIP_DIALOG,
        SipSessionSnortCallback) == false)
        DynamicPreprocessorFatalMessage("failed to subscribe to SIP_DIALOG\n");
#endif
}

void AppIdInspector::show(SnortConfig*)
{
    LogMessage("AppId Configuration\n");

    LogMessage("    Detector Path:          %s\n", config->app_detector_dir);
    LogMessage("    appStats Files:         %s\n", config->app_stats_filename);
    LogMessage("    appStats Period:        %lu secs\n", config->app_stats_period);
    LogMessage("    appStats Rollover Size: %lu bytes\n",
        config->app_stats_rollover_size);
    LogMessage("    appStats Rollover time: %lu secs\n",
        config->app_stats_rollover_time);
    LogMessage("\n");
}

void AppIdInspector::eval(Packet* pkt)
{
    Profile profile(appidPerfStats);

    appid_stats.packets++;
    fwAppIdSearch(pkt);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new AppIdModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void appid_inspector_init()
{
    AppIdData::init();
}

static Inspector* appid_inspector_ctor(Module* m)
{
    AppIdModule* mod = (AppIdModule*)m;
    return new AppIdInspector(mod->get_data());
}

static void appid_inspector_dtor(Inspector* p)
{
    delete p;
}

const InspectApi appid_inspector_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_NETWORK,
    (uint16_t)PktType::ANY_IP,
    nullptr, // buffers
    nullptr, // service
    appid_inspector_init, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    appid_inspector_ctor,
    appid_inspector_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &appid_inspector_api.base,
    nullptr
};
#else
const BaseApi* nin_appid = &appid_inspector_api.base;
#endif

