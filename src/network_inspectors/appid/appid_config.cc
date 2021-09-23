//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "app_info_table.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"
#include "detector_plugins/detector_pattern.h"
#include "host_port_app_cache.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "utils/util.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "target_based/snort_protocols.h"
#include "tp_appid_utils.h"
#include "tp_lib_handler.h"

using namespace snort;

ThirdPartyAppIdContext* AppIdContext::tp_appid_ctxt = nullptr;
OdpContext* AppIdContext::odp_ctxt = nullptr;
uint32_t OdpContext::next_version = 0;

static void map_app_names_to_snort_ids(SnortConfig* sc, AppIdConfig& config)
{
    // Have to create SnortProtocolIds during configuration initialization.
    config.snort_proto_ids[PROTO_INDEX_UNSYNCHRONIZED] = sc->proto_ref->add("unsynchronized");
    config.snort_proto_ids[PROTO_INDEX_FTP_DATA] = sc->proto_ref->add("ftp-data");
    config.snort_proto_ids[PROTO_INDEX_HTTP2] = sc->proto_ref->add("http2");
    config.snort_proto_ids[PROTO_INDEX_REXEC] = sc->proto_ref->add("rexec");
    config.snort_proto_ids[PROTO_INDEX_RSH_ERROR] = sc->proto_ref->add("rsh-error");
    config.snort_proto_ids[PROTO_INDEX_SNMP] = sc->proto_ref->add("snmp");
    config.snort_proto_ids[PROTO_INDEX_SUNRPC] = sc->proto_ref->add("sunrpc");
    config.snort_proto_ids[PROTO_INDEX_TFTP] = sc->proto_ref->add("tftp");
    config.snort_proto_ids[PROTO_INDEX_SIP] = sc->proto_ref->add("sip");
}

AppIdConfig::~AppIdConfig()
{
    snort_free((void*)app_detector_dir);
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
    ConfigLogger::log_value("memcap", static_cast<uint64_t>(memcap));
}

void AppIdContext::pterm()
{
    assert(odp_ctxt);
    odp_ctxt->get_app_info_mgr().cleanup_appid_info_table();
    delete odp_ctxt;

    assert(odp_thread_local_ctxt);
    delete odp_thread_local_ctxt;
    odp_thread_local_ctxt = nullptr;
}

bool AppIdContext::init_appid(SnortConfig* sc, AppIdInspector& inspector)
{
    // do not reload ODP on reload_config()
    if (!odp_ctxt)
        odp_ctxt = new OdpContext(config, sc);

    if (!odp_thread_local_ctxt)
        odp_thread_local_ctxt = new OdpThreadContext;

    static bool once = false;
    if (!once)
    {
        odp_ctxt->get_client_disco_mgr().initialize(inspector);
        odp_ctxt->get_service_disco_mgr().initialize(inspector);
        odp_thread_local_ctxt->initialize(*this, true);
        odp_ctxt->initialize(inspector);

        // do not reload third party on reload_config()
        if (!tp_appid_ctxt)
            tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(config, *odp_ctxt);
        once = true;
    }
    else
    {
        odp_ctxt->get_client_disco_mgr().reload();
        odp_ctxt->get_service_disco_mgr().reload();
        odp_ctxt->reload();
    }

    map_app_names_to_snort_ids(sc, config);
    if (config.enable_rna_filter)
        discovery_filter = new DiscoveryFilter(config.rna_conf_path);
    return true;
}

void AppIdContext::create_odp_ctxt()
{
    SnortConfig* sc = SnortConfig::get_main_conf();
    SearchTool::set_conf(sc);
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
    efp_ca_matchers.finalize_patterns();
    // sip patterns need to be finalized after http patterns because they
    // are dependent on http patterns
    sip_matchers.finalize_patterns(*this);
    ssl_matchers.finalize_patterns();
    dns_matchers.finalize_patterns();
    ssh_matchers.finalize_patterns();
}

void OdpContext::reload()
{
    assert(service_pattern_detector);
    service_pattern_detector->reload_service_port_patterns();
    assert(client_pattern_detector);
    client_pattern_detector->reload_client_port_patterns();
    service_disco_mgr.reload_service_patterns();
    client_disco_mgr.reload_client_patterns();
    efp_ca_matchers.reload_patterns();
    http_matchers.reload_patterns();
    sip_matchers.reload_patterns();
    ssl_matchers.reload_patterns();
    dns_matchers.reload_patterns();
}

void OdpContext::add_port_service_id(IpProtocol proto, uint16_t port, AppId appid)
{
    if (proto == IpProtocol::TCP)
        tcp_port_only[port] = appid;
    else if (proto == IpProtocol::UDP)
        udp_port_only[port] = appid;
    else
        ErrorMessage("appid: invalid port service for proto %d port %d app %d\n",
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

void OdpThreadContext::initialize(AppIdContext& ctxt, bool is_control, bool reload_odp)
{
    if (!is_control and reload_odp)
        LuaDetectorManager::init_thread_manager(ctxt);
    else
        LuaDetectorManager::initialize(ctxt, is_control? 1 : 0, reload_odp);
}

OdpThreadContext::~OdpThreadContext()
{
    assert(lua_detector_mgr);
    delete lua_detector_mgr;
}
