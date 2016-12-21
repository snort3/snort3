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

#include <openssl/crypto.h>

#include "log/messages.h"
#include "main/thread.h"
#include "profiler/profiler.h"
#include "appid_stats.h"
#include "appid_session.h"
#include "lua_detector_module.h"
#include "lua_detector_api.h"
#include "host_port_app_cache.h"
#include "app_forecast.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_base.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_http.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/detector_pattern.h"
#include "appid_http_event_handler.h"
#include "pub_sub/sip_events.h"

static void dump_appid_stats()
{
    LogMessage("Application Identification Preprocessor:\n");
    LogMessage("   Total packets received : %" PRIu64 "\n", appid_stats.packets);
    LogMessage("  Total packets processed : %" PRIu64 "\n", appid_stats.processed_packets);
    if (thirdparty_appid_module)
        thirdparty_appid_module->print_stats();
    LogMessage("    Total packets ignored : %" PRIu64 "\n", appid_stats.ignored_packets);
    AppIdServiceState::dump_stats();
}

// FIXIT-L - appid cleans up openssl now as it is the primary (only) user... eventually this
//           should probably be done outside of appid
static void openssl_cleanup()
{
     CRYPTO_cleanup_all_ex_data();
}

AppIdInspector::AppIdInspector(const AppIdModuleConfig* pc)
{
    assert(pc);
    config = pc;
}

AppIdInspector::~AppIdInspector()
{
    if(config->debug)
        dump_appid_stats();

    delete active_config;
    delete config;
}

bool AppIdInspector::configure(SnortConfig*)
{
    assert(!active_config);
    active_config = new AppIdConfig( ( AppIdModuleConfig* )config);

    get_data_bus().subscribe(HTTP_REQUEST_HEADER_EVENT_KEY, new HttpEventHandler(HttpEventHandler::REQUEST_EVENT));
    get_data_bus().subscribe(HTTP_RESPONSE_HEADER_EVENT_KEY, new HttpEventHandler(HttpEventHandler::RESPONSE_EVENT));
    get_data_bus().subscribe(SIP_EVENT_TYPE_SIP_DIALOG_KEY, new SipEventHandler());

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
    LogMessage("    appStats Logging:       %s\n", config->stats_logging_enabled ? "enabled" : "disabled");
    LogMessage("    appStats Period:        %lu secs\n", config->app_stats_period);
    LogMessage("    appStats Rollover Size: %lu bytes\n",
        config->app_stats_rollover_size);
    LogMessage("    appStats Rollover time: %lu secs\n",
        config->app_stats_rollover_time);
    LogMessage("\n");
    active_config->show();

}

void AppIdInspector::tinit()
{
    init_appid_statistics(*config);
    HostPortCache::initialize();
    init_appid_forecast();
    init_http_detector();
    init_service_plugins();
    init_client_plugins();
    init_detector_plugins();
    init_chp_glossary();
    init_length_app_cache();
    LuaDetectorManager::initialize(*active_config);
    finalize_service_port_patterns();
    finalize_client_port_patterns();
    finalize_service_patterns();
    finalize_client_plugins();
    finalize_http_detector();
    finalize_sip_ua();
    ssl_detector_process_patterns();
    dns_host_detector_process_patterns();
   	AppIdServiceState::initialize(config->memcap);
}

void AppIdInspector::tterm()
{
    cleanup_appid_statistics();

    HostPortCache::terminate();
    clean_appid_forecast();
    service_dns_host_clean();
    service_ssl_clean();
    clean_service_plugins();
    clean_client_plugins();
    clean_http_detector();
    free_chp_glossary();
    free_length_app_cache();

    AppIdSession::release_free_list_flow_data();
    LuaDetectorManager::terminate();
    AppIdServiceState::clean();
}

void AppIdInspector::eval(Packet* pkt)
{
    Profile profile(appidPerfStats);

    appid_stats.packets++;
    AppIdSession::do_application_discovery(pkt);
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

/**
 * @returns 1 if some appid is found, 0 otherwise.
 */
//int sslAppGroupIdLookup(void* ssnptr, const char* serverName, const char* commonName,
//    AppId* serviceAppId, AppId* ClientAppId, AppId* payloadAppId)
int sslAppGroupIdLookup(void*, const char*, const char*, AppId*, AppId*, AppId*)
{
    // FIXIT-M detemine need and proper location for this code when support for ssl is implemented
#ifdef REMOVED_WHILE_NOT_IN_USE
    AppIdSession* asd;
    *serviceAppId = *ClientAppId = *payload_app_id = APP_ID_NONE;

    if (commonName)
    {
        ssl_scan_cname((const uint8_t*)commonName, strlen(commonName), ClientAppId, payload_app_id,
            &AppIdConfig::get_appid_config()->serviceSslConfig);
    }
    if (serverName)
    {
        ssl_scan_hostname((const uint8_t*)serverName, strlen(serverName), ClientAppId,
            payload_app_id, &AppIdConfig::get_appid_config()->serviceSslConfig);
    }

    if (ssnptr && (asd = appid_api.get_appid_data(ssnptr)))
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
    AppIdSession* asd = appid_api.get_appid_data(flow);
    return asd->payload_app_id;
}

