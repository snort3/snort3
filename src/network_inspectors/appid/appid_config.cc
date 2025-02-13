//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// appid_config.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_config.h"

#include <glob.h>
#include <climits>

#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/util.h"
#include "target_based/snort_protocols.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_imap.h"
#include "detector_plugins/detector_kerberos.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_pop3.h"
#include "detector_plugins/detector_smtp.h"
#include "host_port_app_cache.h"
#include "service_plugins/service_ssl.h"
#include "tp_appid_utils.h"
#include "tp_lib_handler.h"
#include "profiler/profiler_defs.h"

using namespace snort;

ThirdPartyAppIdContext* AppIdContext::tp_appid_ctxt = nullptr;
OdpContext* AppIdContext::odp_ctxt = nullptr;
uint32_t OdpContext::next_version = 0;

AppIdConfig::~AppIdConfig()
{
    snort_free((void*)app_detector_dir);
    #ifdef REG_TEST
    snort_free((void*)required_lua_detectors);
    #endif
}

void AppIdConfig::map_app_names_to_snort_ids(SnortConfig& sc)
{
    // Have to create SnortProtocolIds during configuration initialization.
    snort_proto_ids[PROTO_INDEX_UNSYNCHRONIZED] = sc.proto_ref->add("unsynchronized");
    snort_proto_ids[PROTO_INDEX_FTP_DATA] = sc.proto_ref->add("ftp-data");
    snort_proto_ids[PROTO_INDEX_HTTP2] = sc.proto_ref->add("http2");
    snort_proto_ids[PROTO_INDEX_REXEC] = sc.proto_ref->add("rexec");
    snort_proto_ids[PROTO_INDEX_RSH_ERROR] = sc.proto_ref->add("rsh-error");
    snort_proto_ids[PROTO_INDEX_SNMP] = sc.proto_ref->add("snmp");
    snort_proto_ids[PROTO_INDEX_SUNRPC] = sc.proto_ref->add("sunrpc");
    snort_proto_ids[PROTO_INDEX_TFTP] = sc.proto_ref->add("tftp");
    snort_proto_ids[PROTO_INDEX_SIP] = sc.proto_ref->add("sip");
    snort_proto_ids[PROTO_INDEX_SSH] = sc.proto_ref->add("ssh");
    snort_proto_ids[PROTO_INDEX_CIP] = sc.proto_ref->add("cip");
}

void AppIdConfig::show() const
{
    ConfigLogger::log_value("app_detector_dir", app_detector_dir);

    ConfigLogger::log_value("app_stats_period", app_stats_period);
    ConfigLogger::log_value("app_stats_rollover_size", app_stats_rollover_size);

    ConfigLogger::log_flag("list_odp_detectors", list_odp_detectors);

    ConfigLogger::log_value("tp_appid_path", tp_appid_path.c_str());
    ConfigLogger::log_value("tp_appid_config", tp_appid_config.c_str());

    ConfigLogger::log_flag("tp_appid_stats_enable", tp_appid_stats_enable);
    ConfigLogger::log_flag("tp_appid_config_dump", tp_appid_config_dump);

    ConfigLogger::log_flag("log_all_sessions", log_all_sessions);
    ConfigLogger::log_flag("log_stats", log_stats);
    ConfigLogger::log_value("memcap", memcap);
}

static bool once = false;

void AppIdContext::pterm()
{
    delete odp_control_thread_ctxt;
    odp_control_thread_ctxt = nullptr;

    if (odp_ctxt)
    {
        odp_ctxt->get_app_info_mgr().cleanup_appid_info_table();
        if (odp_ctxt->is_appid_cpu_profiler_enabled())
            odp_ctxt->get_appid_cpu_profiler_mgr().display_appid_cpu_profiler_table(*odp_ctxt, APPID_CPU_PROFILER_DEFAULT_DISPLAY_ROWS, true);

        odp_ctxt->get_appid_cpu_profiler_mgr().cleanup_appid_cpu_profiler_table();
        delete odp_ctxt;
        odp_ctxt = nullptr;
    }

    if (appidDebug)
    {
        delete appidDebug;
        appidDebug = nullptr;
    }

    once = false;
}

bool AppIdContext::init_appid(SnortConfig* sc, AppIdInspector& inspector)
{
    // do not reload ODP on reload_config()
    if (!once)
    {
        assert(!odp_ctxt);
        odp_ctxt = new OdpContext(config, sc);
        odp_ctxt->get_client_disco_mgr().initialize(inspector);
        odp_ctxt->get_service_disco_mgr().initialize(inspector);
        odp_ctxt->set_client_and_service_detectors();

        if (!appidDebug)
        {
            appidDebug = new AppIdDebug();
            appidDebug->set_enabled(config.log_all_sessions);
        }

        assert(!odp_control_thread_ctxt);
        odp_control_thread_ctxt = new OdpControlContext;
        odp_control_thread_ctxt->initialize(sc, *this);

        odp_ctxt->initialize(inspector);

        // do not reload third party on reload_config()
        if (!tp_appid_ctxt)
            tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, *odp_ctxt);
        once = true;
    }
    else
    {
        assert(odp_ctxt);
        odp_ctxt->get_client_disco_mgr().reload();
        odp_ctxt->get_service_disco_mgr().reload();
        odp_ctxt->reload();
    }

    if (config.enable_rna_filter)
        discovery_filter = new DiscoveryFilter(config.rna_conf_path);
    return true;
}

void AppIdContext::create_odp_ctxt()
{
    SnortConfig* sc = SnortConfig::get_main_conf();
    odp_ctxt = new OdpContext(config, sc);
}

void AppIdContext::create_tp_appid_ctxt()
{
    tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, *odp_ctxt);
}

void AppIdContext::show() const
{
    config.show();
}

unsigned OdpContext::get_pattern_count()
{
    return service_pattern_detector->get_pattern_count() +
        client_pattern_detector->get_pattern_count() +
        service_disco_mgr.get_pattern_count() +
        client_disco_mgr.get_pattern_count() +
        http_matchers.get_pattern_count() +
        eve_ca_matchers.get_pattern_count() +
        alpn_matchers.get_pattern_count() +
        sip_matchers.get_pattern_count() +
        ssl_matchers.get_pattern_count() +
        ssh_matchers.get_pattern_count() +
        dns_matchers.get_pattern_count();
}

void OdpContext::dump_appid_config()
{
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: dns_host_reporting                   %s\n", (dns_host_reporting ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: referred_appId_disabled              %s\n", (referred_appId_disabled ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: mdns_user_reporting                  %s\n", (mdns_user_reporting ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: chp_userid_disabled                  %s\n", (chp_userid_disabled ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: is_host_port_app_cache_runtime       %s\n", (is_host_port_app_cache_runtime ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: check_host_port_app_cache            %s\n", (check_host_port_app_cache ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: check_host_cache_unknown_ssl         %s\n", (check_host_cache_unknown_ssl ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: ftp_userid_disabled                  %s\n", (ftp_userid_disabled ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: chp_body_collection_disabled         %s\n", (chp_body_collection_disabled ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: chp_body_collection_max              %d\n", chp_body_collection_max);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: rtmp_max_packets                     %d\n", rtmp_max_packets);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: max_tp_flow_depth                    %d\n", max_tp_flow_depth);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: tp_allow_probes                      %s\n", (tp_allow_probes ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: host_port_app_cache_lookup_interval  %d\n", host_port_app_cache_lookup_interval);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: host_port_app_cache_lookup_range     %d\n", host_port_app_cache_lookup_range);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: allow_port_wildcard_host_cache       %s\n", (allow_port_wildcard_host_cache ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: recheck_for_portservice_appid        %s\n", (recheck_for_portservice_appid ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: max_bytes_before_service_fail        %" PRIu64" \n", max_bytes_before_service_fail);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: max_packet_before_service_fail       %" PRIu16" \n", max_packet_before_service_fail);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: max_packet_service_fail_ignore_bytes %" PRIu16" \n", max_packet_service_fail_ignore_bytes);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: eve_http_client                      %s\n", (eve_http_client ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: appid_cpu_profiler                   %s\n", (appid_cpu_profiler ? "True" : "False"));
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: brute_force_inprocess_threshold      %" PRId8" \n", brute_force_inprocess_threshold);
    APPID_LOG(nullptr, TRACE_INFO_LEVEL, "Appid Config: failed_state_expiration_secs         %" PRId32" \n", failed_state_expiration_secs);
}

bool OdpContext::is_appid_cpu_profiler_running()
{
    return (TimeProfilerStats::is_enabled() and appid_cpu_profiler);
}

bool OdpContext::is_appid_cpu_profiler_enabled()
{
    return appid_cpu_profiler;
}

OdpContext::OdpContext(const AppIdConfig& config, SnortConfig* sc)
{
    app_info_mgr.init_appid_info_table(config, sc, *this);
    client_pattern_detector = new PatternClientDetector(&client_disco_mgr);
    service_pattern_detector = new PatternServiceDetector(&service_disco_mgr);
    version = next_version++;
}

void OdpContext::initialize(AppIdInspector& inspector)
{
    service_pattern_detector->finalize_service_port_patterns(inspector);
    client_pattern_detector->finalize_client_port_patterns(inspector);
    service_disco_mgr.finalize_service_patterns();
    client_disco_mgr.finalize_client_patterns();
    http_matchers.finalize_patterns();
    eve_ca_matchers.finalize_patterns();
    alpn_matchers.finalize_patterns();
    // sip patterns need to be finalized after http patterns because they
    // are dependent on http patterns
    sip_matchers.finalize_patterns(*this);
    ssl_matchers.finalize_patterns();
    dns_matchers.finalize_patterns();
}

void OdpContext::reload()
{
    assert(service_pattern_detector);
    service_pattern_detector->reload_service_port_patterns();
    assert(client_pattern_detector);
    client_pattern_detector->reload_client_port_patterns();
    service_disco_mgr.reload_service_patterns();
    client_disco_mgr.reload_client_patterns();
    eve_ca_matchers.reload_patterns();
    http_matchers.reload_patterns();
    sip_matchers.reload_patterns();
    ssl_matchers.reload_patterns();
    dns_matchers.reload_patterns();
    alpn_matchers.reload_patterns();
}

void OdpContext::set_client_and_service_detectors()
{
    Pop3ServiceDetector* s_pop = (Pop3ServiceDetector*) service_disco_mgr.get_service_detector("pop3");
    Pop3ClientDetector* c_pop = (Pop3ClientDetector*) client_disco_mgr.get_client_detector("pop3");
    if (!s_pop or !c_pop)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize pop3 detector\n");
        return;
    }
    s_pop->set_client_detector(c_pop);
    c_pop->set_service_detector(s_pop);

    KerberosServiceDetector* s_krb = (KerberosServiceDetector*) service_disco_mgr.get_service_detector("kerberos");
    KerberosClientDetector* c_krb = (KerberosClientDetector*) client_disco_mgr.get_client_detector("kerberos");
    if (!s_krb or !c_krb)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize kerberos detector\n");
        return;
    }
    s_krb->set_client_detector(c_krb);
    c_krb->set_service_detector(s_krb);

    SmtpServiceDetector* s_smtp = (SmtpServiceDetector*) service_disco_mgr.get_service_detector("smtp");
    SmtpClientDetector* c_smtp = (SmtpClientDetector*) client_disco_mgr.get_client_detector("SMTP");
    if (!s_smtp or !c_smtp)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize smtp detector\n");
        return;
    }
    s_smtp->set_client_detector(c_smtp);

    ImapServiceDetector* s_imap = (ImapServiceDetector*) service_disco_mgr.get_service_detector("IMAP");
    ImapClientDetector* c_imap = (ImapClientDetector*) client_disco_mgr.get_client_detector("IMAP");
    if (!s_imap or !c_imap)
    {
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize imap detector\n");
        return;
    }
    s_imap->set_client_detector(c_imap);
}

SipServiceDetector* OdpContext::get_sip_service_detector()
{
    SipServiceDetector* s_sip = (SipServiceDetector*) service_disco_mgr.get_service_detector("sip");
    if (!s_sip)
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize sip service detector\n");
    return s_sip;
}

SipUdpClientDetector* OdpContext::get_sip_client_detector()
{
    SipUdpClientDetector* c_sip = (SipUdpClientDetector*) client_disco_mgr.get_client_detector("SIP");
    if (!c_sip)
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: failed to initialize sip client detector\n");
    return c_sip;
}

void OdpContext::add_port_service_id(IpProtocol proto, uint16_t port, AppId appid)
{
    if (proto == IpProtocol::TCP)
        tcp_port_only[port] = appid;
    else if (proto == IpProtocol::UDP)
        udp_port_only[port] = appid;
    else
        APPID_LOG(nullptr, TRACE_ERROR_LEVEL, "appid: invalid port service for proto %d port %d app %d\n",
            static_cast<int>(proto), port, appid);
}

void OdpContext::add_protocol_service_id(IpProtocol proto, AppId appid)
{
    ip_protocol[static_cast<uint16_t>(proto)] = appid;
}

AppId OdpContext::get_port_service_id(IpProtocol proto, uint16_t port)
{
    AppId appId;

    if (proto == IpProtocol::TCP)
        appId = tcp_port_only[port];
    else
        appId = udp_port_only[port];

    return appId;
}

AppId OdpContext::get_protocol_service_id(IpProtocol proto)
{
    return ip_protocol[(uint16_t)proto];
}

void OdpControlContext::initialize(const SnortConfig* sc, AppIdContext& ctxt)
{
    lua_detector_mgr = std::make_shared<ControlLuaDetectorManager>(ctxt);
    lua_detector_mgr->initialize(sc);
}

void OdpPacketThreadContext::initialize(const SnortConfig* sc)
{
    lua_detector_mgr = ControlLuaDetectorManager::get_packet_lua_detector_manager();
    assert(lua_detector_mgr);
    lua_detector_mgr->initialize(sc);
}
