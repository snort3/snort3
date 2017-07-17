//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_module.h"
#include "appid_stats.h"
#include "appid_session.h"
#include "appid_discovery.h"
#include "host_port_app_cache.h"
#include "app_forecast.h"
#include "lua_detector_module.h"
#include "appid_http_event_handler.h"
#include "thirdparty_appid_utils.h"
#include "client_plugins/client_discovery.h"
#include "service_plugins/service_discovery.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/http_url_patterns.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/detector_pattern.h"
#include "log/messages.h"
#include "log/packet_tracer.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "target_based/snort_protocols.h"

static THREAD_LOCAL AppIdStatistics* appid_stats_manager = nullptr;

// FIXIT-L - appid cleans up openssl now as it is the primary (only) user... eventually this
//           should probably be done outside of appid
static void openssl_cleanup()
{
    CRYPTO_cleanup_all_ex_data();
}

static void add_appid_to_packet_trace(Flow* flow)
{
    AppIdSession* session = appid_api.get_appid_session(flow);
    if (session)
    {
        AppId service_id, client_id, payload_id, misc_id;
        const char *service_app_name, *client_app_name, *payload_app_name, *misc_name;
        session->get_application_ids(service_id, client_id, payload_id, misc_id);
        service_app_name = appid_api.get_application_name(service_id);
        client_app_name = appid_api.get_application_name(client_id);
        payload_app_name = appid_api.get_application_name(payload_id);
        misc_name = appid_api.get_application_name(misc_id);

        PacketTracer::log("AppID: service: %s(%d), client: %s(%d), payload: %s(%d), misc: %s(%d)\n",
            (service_app_name ? service_app_name : ""), service_id,
            (client_app_name ? client_app_name : ""), client_id,
            (payload_app_name ? payload_app_name : ""), payload_id,
            (misc_name ? misc_name : ""), misc_id);
    }
}

AppIdInspector::AppIdInspector(const AppIdModuleConfig* pc)
{
    assert(pc);
    config = pc;
}

AppIdInspector::~AppIdInspector()
{
    delete active_config;
    delete config;
}

AppIdInspector* AppIdInspector::get_inspector()
{
    return (AppIdInspector*)InspectorManager::get_inspector(MOD_NAME);
}

AppIdConfig* AppIdInspector::get_appid_config()
{
    return active_config;
}

AppIdStatistics* AppIdInspector::get_stats_manager()
{
    return appid_stats_manager;
}

int16_t AppIdInspector::add_appid_protocol_reference(const char* protocol)
{
    static std::mutex apr_mutex;

    apr_mutex.lock();
    int16_t id = snort_conf->proto_ref->add(protocol);
    apr_mutex.unlock();
    return id;
}

bool AppIdInspector::configure(SnortConfig*)
{
    assert(!active_config);

    active_config = new AppIdConfig( ( AppIdModuleConfig* )config);

    get_data_bus().subscribe(HTTP_REQUEST_HEADER_EVENT_KEY, new HttpEventHandler(
        HttpEventHandler::REQUEST_EVENT));
    get_data_bus().subscribe(HTTP_RESPONSE_HEADER_EVENT_KEY, new HttpEventHandler(
        HttpEventHandler::RESPONSE_EVENT));

    my_seh = SipEventHandler::create();
    my_seh->subscribe();

    return active_config->init_appid();

    // FIXIT-M some of this stuff may be needed in some fashion...
#ifdef REMOVED_WHILE_NOT_IN_USE
    _dpd.registerGeAppId(getOpenAppId);
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
    appid_stats_manager = AppIdStatistics::initialize_manager(*config);
    HostPortCache::initialize();
    AppIdServiceState::initialize();
    init_appid_forecast();
    HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
    AppIdDiscovery::initialize_plugins();
    init_length_app_cache();
    LuaDetectorManager::initialize(*active_config);
    PatternServiceDetector::finalize_service_port_patterns();
    PatternClientDetector::finalize_client_port_patterns();
    AppIdDiscovery::finalize_plugins();
    http_matchers->finalize();
    SipUdpClientDetector::finalize_sip_ua();
    ssl_detector_process_patterns();
    dns_host_detector_process_patterns();
}

void AppIdInspector::tterm()
{
    delete appid_stats_manager;
    HostPortCache::terminate();
    clean_appid_forecast();
    service_dns_host_clean();
    service_ssl_clean();
    free_length_app_cache();

    AppIdServiceState::clean();
    LuaDetectorManager::terminate();
    AppIdDiscovery::release_plugins();
    delete HttpPatternMatchers::get_instance();
}

void AppIdInspector::eval(Packet* p)
{
    Profile profile(appidPerfStats);

    appid_stats.packets++;
    if (p->flow)
    {
        AppIdDiscovery::do_application_discovery(p);
        if (SnortConfig::packet_trace_enabled())
            add_appid_to_packet_trace(p->flow);
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
}

static void appid_inspector_pterm()
{
    openssl_cleanup();
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
    appid_inspector_pinit, // pinit
    appid_inspector_pterm, // pterm
    nullptr, // tinit
    nullptr, // tterm
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
//    AppId* serviceAppId, AppId* ClientAppId, AppId* payloadAppId)
int sslAppGroupIdLookup(void*, const char*, const char*, AppId*, AppId*, AppId*)
{
    // FIXIT-M determine need and proper location for this code when support for ssl is implemented
    //         also once this is done the call to get the appid config should change to use the
    //         config assigned to the flow being processed
#ifdef REMOVED_WHILE_NOT_IN_USE
    AppIdSession* asd;
    *serviceAppId = *ClientAppId = *payload_app_id = APP_ID_NONE;

    if (commonName)
    {
        ssl_scan_cname((const uint8_t*)commonName, strlen(commonName), ClientAppId, payload_app_id,
            &AppIdInspector::get_inspector()->get_appid_config()->serviceSslConfig);
    }
    if (serverName)
    {
        ssl_scan_hostname((const uint8_t*)serverName, strlen(serverName), ClientAppId,
            payload_app_id,
            &AppIdInspector::get_inspector()->get_appid_config()->serviceSslConfig);
    }

    if (ssnptr && (asd = appid_api.get_appid_session(ssnptr)))
    {
        *serviceAppId = pick_service_app_id(asd);
        if (*ClientAppId == APP_ID_NONE)
        {
            *ClientAppId = pick_client_app_id(asd);
        }
        if (*payload_app_id == APP_ID_NONE)
        {
            *payload_app_id = pick_payload_app_id(asd);
        }
    }
    if (*serviceAppId != APP_ID_NONE ||
        *ClientAppId != APP_ID_NONE ||
        *payload_app_id != APP_ID_NONE)
    {
        return 1;
    }
#endif

    return 0;
}

AppId getOpenAppId(Flow* flow)
{
    assert(flow);
    AppIdSession* asd = appid_api.get_appid_session(flow);
    return asd->payload_app_id;
}
