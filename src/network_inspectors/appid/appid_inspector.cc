//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <sys/resource.h>

#include "flow/flow.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/intrinsic_event_ids.h"

#include "appid_cip_event_handler.h"
#include "appid_data_decrypt_event_handler.h"
#include "appid_dcerpc_event_handler.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_eve_process_event_handler.h"
#include "appid_ha.h"
#include "appid_http_event_handler.h"
#include "appid_httpx_req_body_event_handler.h"
#include "appid_opportunistic_tls_event_handler.h"
#include "appid_peg_counts.h"
#include "appid_service_event_handler.h"
#include "appid_session.h"
#include "appid_ssh_event_handler.h"
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
THREAD_LOCAL ThirdPartyAppIdContext* pkt_thread_tp_appid_ctxt = nullptr;
OdpControlContext* odp_control_thread_ctxt = nullptr;
THREAD_LOCAL OdpPacketThreadContext* odp_thread_local_ctxt = nullptr;
THREAD_LOCAL OdpContext* pkt_thread_odp_ctxt = nullptr;

unsigned AppIdInspector::cached_global_pub_id = 0;
static THREAD_LOCAL unsigned appid_pub_id = 0;

static THREAD_LOCAL PacketTracer::TracerMute appid_mute;

static void add_appid_to_packet_trace(const Flow& flow, const OdpContext& odp_context)
{
    AppIdSession* session = appid_api.get_appid_session(flow);
    // Skip sessions using old odp context after odp reload
    if (!session or (session->get_odp_ctxt_version() != odp_context.get_version()))
        return;

    AppId service_id, client_id, payload_id, misc_id;
    const char* service_app_name, * client_app_name, * payload_app_name, * misc_name;
    OdpContext& odp_ctxt = session->get_odp_ctxt();
    session->get_api().get_first_stream_app_ids(service_id, client_id, payload_id, misc_id);
    service_app_name = appid_api.get_application_name(service_id, odp_ctxt);
    client_app_name = appid_api.get_application_name(client_id, odp_ctxt);
    payload_app_name = appid_api.get_application_name(payload_id, odp_ctxt);
    misc_name = appid_api.get_application_name(misc_id, odp_ctxt);

    PacketTracer::log(appid_mute,
        "AppID: service: %s(%d), client: %s(%d), payload: %s(%d), misc: %s(%d)\n",
        (service_app_name ? service_app_name : ""), service_id,
        (client_app_name ? client_app_name : ""), client_id,
        (payload_app_name ? payload_app_name : ""), payload_id,
        (misc_name ? misc_name : ""), misc_id);
}

AppIdInspector::AppIdInspector(AppIdModule& mod) : config(mod.get_data()), ctxt(*config)
{
}

AppIdInspector::~AppIdInspector()
{
    delete config;
}

unsigned AppIdInspector::get_pub_id()
{
    return appid_pub_id;
}

bool AppIdInspector::configure(SnortConfig* sc)
{
    // cppcheck-suppress unreadVariable
    Profile profile(appid_perf_stats);
    struct rusage ru;
    long prev_maxrss = -1;
    #ifdef REG_TEST
    if ( config->log_memory_and_pattern_count )
    {
    #endif
        if ( getrusage(RUSAGE_SELF, &ru) == 0 )
            prev_maxrss = ru.ru_maxrss;
    #ifdef REG_TEST
    }
    #endif

    assert(sc);
    config->map_app_names_to_snort_ids(*sc);
    ctxt.init_appid(sc, *this);

    #ifdef REG_TEST
    if ( config->log_memory_and_pattern_count )
    {
    #endif
        if ( prev_maxrss == -1 or getrusage(RUSAGE_SELF, &ru) == -1 )
            APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: fetching memory usage failed\n");
        else
            APPID_LOG(nullptr, TRACE_INFO_LEVEL, "appid: MaxRss diff: %li\n", ru.ru_maxrss - prev_maxrss);
        APPID_LOG(nullptr, TRACE_INFO_LEVEL, "appid: patterns loaded: %u\n", ctxt.get_odp_ctxt().get_pattern_count());
    #ifdef REG_TEST
    }
    #endif

    DataBus::subscribe_global(http_pub_key, HttpEventIds::REQUEST_HEADER,
        new HttpEventHandler(HttpEventHandler::REQUEST_EVENT, *this), *sc);

    DataBus::subscribe_global(http_pub_key, HttpEventIds::RESPONSE_HEADER,
        new HttpEventHandler(HttpEventHandler::RESPONSE_EVENT, *this), *sc);

    DataBus::subscribe_global(http_pub_key, HttpEventIds::REQUEST_BODY, new AppIdHttpXReqBodyEventHandler(), *sc);
    DataBus::subscribe_global(sip_pub_key, SipEventIds::DIALOG, new SipEventHandler(*this), *sc);
    DataBus::subscribe_global(dce_tcp_pub_key, DceTcpEventIds::EXP_SESSION, new DceExpSsnEventHandler(), *sc);
    DataBus::subscribe_global(ssh_pub_key, SshEventIds::STATE_CHANGE, new SshEventHandler(), *sc);
    DataBus::subscribe_global(cip_pub_key, CipEventIds::DATA, new CipEventHandler(*this), *sc);
    DataBus::subscribe_global(external_pub_key, ExternalEventIds::DATA_DECRYPT, new DataDecryptEventHandler(*this), *sc);

    DataBus::subscribe_global(external_pub_key, ExternalEventIds::EVE_PROCESS,
        new AppIdEveProcessEventHandler(*this), *sc);

    DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::OPPORTUNISTIC_TLS,
        new AppIdOpportunisticTlsEventHandler(), *sc);

    DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::FLOW_NO_SERVICE,
         new AppIdServiceEventHandler(*this), *sc);

    if (!cached_global_pub_id)
        cached_global_pub_id = DataBus::get_id(appid_pub_key);

    appid_pub_id = cached_global_pub_id;
    return true;
}

void AppIdInspector::show(const SnortConfig*) const
{
    config->show();
}

void AppIdInspector::tinit()
{
    appid_pub_id = cached_global_pub_id;
    appid_mute = PacketTracer::get_mute();

    AppIdStatistics::initialize_manager(*config);

    assert(!pkt_thread_odp_ctxt);
    pkt_thread_odp_ctxt = &ctxt.get_odp_ctxt();

    assert(!odp_thread_local_ctxt);
    odp_thread_local_ctxt = new OdpPacketThreadContext;
    odp_thread_local_ctxt->initialize(SnortConfig::get_conf());

    AppIdServiceState::initialize(config->memcap);
    AppIdServiceState::set_service_thresholds(pkt_thread_odp_ctxt->failed_state_expiration_secs, pkt_thread_odp_ctxt->brute_force_inprocess_threshold);
    assert(!pkt_thread_tp_appid_ctxt);
    pkt_thread_tp_appid_ctxt = ctxt.get_tp_appid_ctxt();
    if (pkt_thread_tp_appid_ctxt)
        pkt_thread_tp_appid_ctxt->tinit();
    if (config->log_all_sessions)
        appidDebug->set_enabled(true);
     if ( snort::HighAvailabilityManager::active() )
        AppIdHAManager::tinit();
    ServiceDiscovery::set_thread_local_ftp_service();
}

void AppIdInspector::tterm()
{
    AppIdStatistics::cleanup();
    AppIdDiscovery::tterm();
    assert(odp_thread_local_ctxt);
    delete odp_thread_local_ctxt;
    odp_thread_local_ctxt = nullptr;
    if (pkt_thread_tp_appid_ctxt)
        pkt_thread_tp_appid_ctxt->tfini();
    if ( snort::HighAvailabilityManager::active() )
        AppIdHAManager::tterm();
    ServiceDiscovery::reset_thread_local_ftp_service();
}

void AppIdInspector::tear_down(SnortConfig*)
{
    main_broadcast_command(new ACThirdPartyAppIdCleanup());
}

void AppIdInspector::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(appid_perf_stats);
    appid_stats.packets++;


    if (p->flow)
    {
        if (PacketTracer::is_daq_activated())
            PacketTracer::restart_timer();

        AppIdDiscovery::do_application_discovery(p, *this, *pkt_thread_odp_ctxt, pkt_thread_tp_appid_ctxt);
        // FIXIT-L tag verdict reason as appid for daq
        if (PacketTracer::is_active())
            add_appid_to_packet_trace(*p->flow, *pkt_thread_odp_ctxt);
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
    AppIdPegCounts::init_peg_info();
}

static void appid_inspector_pterm()
{
    AppIdContext::pterm();
    TPLibHandler::pfini();
    AppIdPegCounts::cleanup_peg_info();
}

static void appid_inspector_tinit()
{
    AppIdPegCounts::init_pegs();
    if (!appidDebug)
        appidDebug = new AppIdDebug();
}

static void appid_inspector_tterm()
{
    TPLibHandler::tfini();
    AppIdPegCounts::sum_stats();
    AppIdPegCounts::cleanup_pegs();
    AppIdServiceState::clean();
    delete appidDebug;
    appidDebug = nullptr;
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

