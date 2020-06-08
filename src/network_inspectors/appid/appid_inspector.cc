//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_inspector.h"

#include <openssl/crypto.h>

#include "flow/flow.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "packet_tracer/packet_tracer.h"
#include "profiler/profiler.h"

#include "app_forecast.h"
#include "appid_data_decrypt_event_handler.h"
#include "appid_dcerpc_event_handler.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_http_event_handler.h"
#include "appid_peg_counts.h"
#include "appid_session.h"
#include "appid_stats.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_sip.h"
#include "host_port_app_cache.h"
#include "lua_detector_module.h"
#include "service_plugins/service_discovery.h"
#include "tp_appid_module_api.h"
#include "tp_lib_handler.h"

using namespace snort;
THREAD_LOCAL ThirdPartyAppIdContext* tp_appid_thread_ctxt = nullptr;
static THREAD_LOCAL PacketTracer::TracerMute appid_mute;

// FIXIT-L - appid cleans up openssl now as it is the primary (only) user... eventually this
//           should probably be done outside of appid
static void openssl_cleanup()
{
    CRYPTO_cleanup_all_ex_data();
}

static void add_appid_to_packet_trace(Flow& flow)
{
    AppIdSession* session = appid_api.get_appid_session(flow);
    if (session)
    {
        AppId service_id, client_id, payload_id, misc_id;
        const char* service_app_name, * client_app_name, * payload_app_name, * misc_name;
        session->get_first_stream_app_ids(service_id, client_id, payload_id, misc_id);
        service_app_name = appid_api.get_application_name(service_id, session->ctxt);
        client_app_name = appid_api.get_application_name(client_id, session->ctxt);
        payload_app_name = appid_api.get_application_name(payload_id, session->ctxt);
        misc_name = appid_api.get_application_name(misc_id, session->ctxt);

        if (PacketTracer::is_active())
        {
            PacketTracer::log(appid_mute,
                    "AppID: service: %s(%d), client: %s(%d), payload: %s(%d), misc: %s(%d)\n",
                    (service_app_name ? service_app_name : ""), service_id,
                    (client_app_name ? client_app_name : ""), client_id,
                    (payload_app_name ? payload_app_name : ""), payload_id,
                    (misc_name ? misc_name : ""), misc_id);
        }
    }
}

AppIdInspector::AppIdInspector(AppIdModule& mod)
{
    config = mod.get_data();
    assert(config);
}

AppIdInspector::~AppIdInspector()
{
    if (ctxt)
        delete ctxt;
    delete config;
}

AppIdContext& AppIdInspector::get_ctxt() const
{
    assert(ctxt);
    return *ctxt;
}

bool AppIdInspector::configure(SnortConfig* sc)
{
    assert(!ctxt);

    ctxt = new AppIdContext(const_cast<AppIdConfig&>(*config));

    my_seh = SipEventHandler::create();
    my_seh->subscribe(sc);

    ctxt->init_appid(sc);

    DataBus::subscribe_global(HTTP_REQUEST_HEADER_EVENT_KEY, new HttpEventHandler(
        HttpEventHandler::REQUEST_EVENT), sc);

    DataBus::subscribe_global(HTTP_RESPONSE_HEADER_EVENT_KEY, new HttpEventHandler(
        HttpEventHandler::RESPONSE_EVENT), sc);

    DataBus::subscribe_global(DATA_DECRYPT_EVENT, new DataDecryptEventHandler(), sc);

    DataBus::subscribe_global(DCERPC_EXP_SESSION_EVENT_KEY, new DceExpSsnEventHandler(), sc);

    return true;
}

void AppIdInspector::show(const SnortConfig*) const
{
    config->show();
}

void AppIdInspector::tinit()
{
    appid_mute = PacketTracer::get_mute();

    AppIdStatistics::initialize_manager(*config);
    LuaDetectorManager::initialize(*ctxt);
    AppIdServiceState::initialize(config->memcap);
    assert(!tp_appid_thread_ctxt);
    tp_appid_thread_ctxt = ctxt->get_tp_appid_ctxt();
    if (tp_appid_thread_ctxt)
        tp_appid_thread_ctxt->tinit();
    if (ctxt->config.log_all_sessions)
        appidDebug->set_enabled(true);
}

void AppIdInspector::tterm()
{
    AppIdStatistics::cleanup();
    AppIdDiscovery::tterm();
    ThirdPartyAppIdContext* tp_appid_ctxt = ctxt->get_tp_appid_ctxt();
    if (tp_appid_ctxt)
        tp_appid_ctxt->tfini();
}

void AppIdInspector::eval(Packet* p)
{
    Profile profile(appid_perf_stats);
    appid_stats.packets++;

    if (p->flow)
    {
        AppIdDiscovery::do_application_discovery(p, *this, tp_appid_thread_ctxt);
        // FIXIT-L tag verdict reason as appid for daq
        if (PacketTracer::is_active())
            add_appid_to_packet_trace(*p->flow);
    }
    else
        appid_stats.ignored_packets++;
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

static void appid_inspector_pinit()
{
    AppIdSession::init();
    TPLibHandler::get();
}

static void appid_inspector_pterm()
{
//FIXIT-M: RELOAD - if app_info_table is associated with an object
    appid_forecast_pterm();
    LuaDetectorManager::terminate();
    AppIdContext::pterm();
//end of 'FIXIT-M: RELOAD' comment above
    openssl_cleanup();
    TPLibHandler::pfini();
}

static void appid_inspector_tinit()
{
    AppIdPegCounts::init_pegs();
    appid_forecast_tinit();
    appidDebug = new AppIdDebug();
}

static void appid_inspector_tterm()
{
    TPLibHandler::tfini();
    AppIdPegCounts::cleanup_pegs();
    LuaDetectorManager::terminate();
    AppIdServiceState::clean();
    appid_forecast_tterm();
    delete appidDebug;
}

static Inspector* appid_inspector_ctor(Module* m)
{
    assert(m);
    return new AppIdInspector((AppIdModule&)*m);
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
    IT_CONTROL,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    appid_inspector_pinit,
    appid_inspector_pterm,
    appid_inspector_tinit,
    appid_inspector_tterm,
    appid_inspector_ctor,
    appid_inspector_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_appid;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_appid[] =
#endif
{
    &appid_inspector_api.base,
    ips_appid,
    nullptr
};

