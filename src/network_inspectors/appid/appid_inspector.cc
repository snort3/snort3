//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "packet_tracer/packet_tracer.h"
#include "profiler/profiler.h"

#include "app_forecast.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_http_event_handler.h"
#include "appid_session.h"
#include "appid_stats.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/http_url_patterns.h"
#include "host_port_app_cache.h"
#include "lua_detector_module.h"
#include "service_plugins/service_discovery.h"
#include "service_plugins/service_ssl.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_lib_handler.h"
#endif

using namespace snort;
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
        session->get_application_ids(service_id, client_id, payload_id, misc_id);
        service_app_name = appid_api.get_application_name(service_id);
        client_app_name = appid_api.get_application_name(client_id);
        payload_app_name = appid_api.get_application_name(payload_id);
        misc_name = appid_api.get_application_name(misc_id);

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
}

AppIdInspector::~AppIdInspector()
{
    delete active_config;
    delete config;
}

AppIdConfig* AppIdInspector::get_appid_config()
{
    return active_config;
}

bool AppIdInspector::configure(SnortConfig* sc)
{
    assert(!active_config);

    active_config = new AppIdConfig(const_cast<AppIdModuleConfig*>(config));

    my_seh = SipEventHandler::create();
    my_seh->subscribe();

    active_config->init_appid(sc, this);

#ifdef ENABLE_APPID_THIRD_PARTY
    if (!TPLibHandler::have_tp())
#endif
    {
        DataBus::subscribe(HTTP_REQUEST_HEADER_EVENT_KEY, new HttpEventHandler(
            HttpEventHandler::REQUEST_EVENT));

        DataBus::subscribe(HTTP_RESPONSE_HEADER_EVENT_KEY, new HttpEventHandler(
            HttpEventHandler::RESPONSE_EVENT));
    }

    return true;

    // FIXIT-M some of this stuff may be needed in some fashion...
#ifdef REMOVED_WHILE_NOT_IN_USE
    _dpd.registerSslAppIdLookup(sslAppGroupIdLookup);
#endif
}

void AppIdInspector::show(SnortConfig*)
{
    LogMessage("AppId Configuration\n");

    LogMessage("    Detector Path:          %s\n", config->app_detector_dir);
    LogMessage("    appStats Logging:       %s\n", config->stats_logging_enabled ? "enabled" :
        "disabled");
    LogMessage("    appStats Period:        %lu secs\n", config->app_stats_period);
    LogMessage("    appStats Rollover Size: %lu bytes\n",
        config->app_stats_rollover_size);
    LogMessage("    appStats Rollover time: %lu secs\n",
        config->app_stats_rollover_time);
    LogMessage("\n");
}

void AppIdInspector::tinit()
{
    appid_mute = PacketTracer::get_mute();

    AppIdStatistics::initialize_manager(*config);
    appid_forecast_tinit();
    LuaDetectorManager::initialize(*active_config);
    AppIdServiceState::initialize();
    appidDebug = new AppIdDebug();
    if (active_config->mod_config and active_config->mod_config->log_all_sessions)
        appidDebug->set_enabled(true);
#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::tinit();
#endif
}

void AppIdInspector::tterm()
{
    appid_forecast_tterm();
    AppIdStatistics::cleanup();
    LuaDetectorManager::terminate();
    AppIdDiscovery::tterm();
    AppIdServiceState::clean();
    delete appidDebug;
    appidDebug = nullptr;
#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::tterm();
#endif
}

void AppIdInspector::eval(Packet* p)
{
    Profile profile(appidPerfStats);
    appid_stats.packets++;
    
    if (p->flow)
    {
        AppIdDiscovery::do_application_discovery(p, *this);
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
#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::get();
#endif
}

static void appid_inspector_pterm()
{
//FIXIT-M: RELOAD - if app_info_table is associated with an object
    HostPortCache::terminate();
    appid_forecast_pterm();
    free_length_app_cache();
    LuaDetectorManager::terminate();
    AppIdDiscovery::release_plugins();
    delete HttpPatternMatchers::get_instance();
    service_dns_host_clean();
    service_ssl_clean();
    AppIdConfig::pterm();
//end of 'FIXIT-M: RELOAD' comment above
    openssl_cleanup();
#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::pfini();
#endif
}

static void appid_inspector_tinit()
{
    AppIdPegCounts::init_pegs();
}

static void appid_inspector_tterm()
{
    AppIdPegCounts::cleanup_pegs();
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

// @returns 1 if some appid is found, 0 otherwise.
//int sslAppGroupIdLookup(void* ssnptr, const char* serverName, const char* commonName,
//    AppId* service_id, AppId* client_id, AppId* payload_id)
int sslAppGroupIdLookup(void*, const char*, const char*, AppId*, AppId*, AppId*)
{
    // FIXIT-M determine need and proper location for this code when support for ssl is implemented
    //         also once this is done the call to get the appid config should change to use the
    //         config assigned to the flow being processed
#ifdef REMOVED_WHILE_NOT_IN_USE
    AppIdSession* asd;
    *service_id = *client_id = *payload_id = APP_ID_NONE;

    if (commonName)
    {
        ssl_scan_cname((const uint8_t*)commonName, strlen(commonName), client_id, payload_app_id,
            &get_appid_config()->serviceSslConfig);
    }
    if (serverName)
    {
        ssl_scan_hostname((const uint8_t*)serverName, strlen(serverName), client_id,
            payload_app_id, &get_appid_config()->serviceSslConfig);
    }

    if (ssnptr && (asd = appid_api.get_appid_session(ssnptr)))
        asd->get_application_ids(*service_id, *client_id, *payload_id);

    if (*service_id != APP_ID_NONE ||
        *client_id != APP_ID_NONE ||
        *payload_id != APP_ID_NONE)
    {
        return 1;
    }
#endif

    return 0;
}
