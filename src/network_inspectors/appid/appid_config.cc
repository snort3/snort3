//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_session.h"
#include "detector_plugins/detector_pattern.h"
#include "host_port_app_cache.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "lua_detector_module.h"
#include "utils/util.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "target_based/snort_protocols.h"
#include "tp_appid_utils.h"
#include "tp_lib_handler.h"

using namespace snort;

SnortProtocolId snortId_for_unsynchronized;
SnortProtocolId snortId_for_ftp_data;
SnortProtocolId snortId_for_http2;

ThirdPartyAppIdContext* AppIdContext::tp_appid_ctxt = nullptr;
OdpContext* AppIdContext::odp_ctxt = nullptr;

static void map_app_names_to_snort_ids(SnortConfig* sc)
{
    /* init globals for snortId compares */
    snortId_for_unsynchronized = sc->proto_ref->add("unsynchronized");
    snortId_for_ftp_data = sc->proto_ref->add("ftp-data");
    snortId_for_http2    = sc->proto_ref->add("http2");

    // Have to create SnortProtocolIds during configuration initialization.
    sc->proto_ref->add("rexec");
    sc->proto_ref->add("rsh-error");
    sc->proto_ref->add("snmp");
    sc->proto_ref->add("sunrpc");
    sc->proto_ref->add("tftp");
}

AppIdConfig::~AppIdConfig()
{
    snort_free((void*)app_detector_dir);
}

// FIXIT-M: RELOAD - move initialization back to AppIdContext class constructor
AppInfoManager& AppIdContext::app_info_mgr = AppInfoManager::get_instance();
std::array<AppId, APP_ID_PORT_ARRAY_SIZE> AppIdContext::tcp_port_only = {APP_ID_NONE};
std::array<AppId, APP_ID_PORT_ARRAY_SIZE> AppIdContext::udp_port_only = {APP_ID_NONE};
std::array<AppId, 256> AppIdContext::ip_protocol = {APP_ID_NONE};

// FIXIT-M: RELOAD - Move app info table cleanup back to AppId config destructor - cleanup()
void AppIdContext::pterm()
{
    AppIdContext::app_info_mgr.cleanup_appid_info_table();
}

bool AppIdContext::init_appid(SnortConfig* sc)
{
    // do not reload ODP on reload_config()
    if (!odp_ctxt)
        odp_ctxt = new OdpContext();

    // FIXIT-M: RELOAD - Get rid of "once" flag
    // Handle the if condition in AppIdContext::init_appid
    static bool once = false;
    if (!once)
    {
        AppIdContext::app_info_mgr.init_appid_info_table(config, sc, *odp_ctxt);
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
        AppIdDiscovery::initialize_plugins();
        LuaDetectorManager::initialize(*this, 1);
        PatternServiceDetector::finalize_service_port_patterns();
        PatternClientDetector::finalize_client_port_patterns();
        AppIdDiscovery::finalize_plugins();
        http_matchers->finalize_patterns();
        ssl_detector_process_patterns();
        dns_host_detector_process_patterns();
        once = true;
    }

    // do not reload third party on reload_config()
    if (!tp_appid_ctxt)
        tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(*config, *odp_ctxt);

    map_app_names_to_snort_ids(sc);
    return true;
}

void AppIdContext::create_tp_appid_ctxt()
{
    tp_appid_ctxt = TPLibHandler::create_tp_appid_ctxt(*config, *odp_ctxt);
}

AppId AppIdContext::get_port_service_id(IpProtocol proto, uint16_t port)
{
    AppId appId;

    if (proto == IpProtocol::TCP)
        appId = tcp_port_only[port];
    else
        appId = udp_port_only[port];

    return appId;
}

AppId AppIdContext::get_protocol_service_id(IpProtocol proto)
{
    return ip_protocol[(uint16_t)proto];
}

void AppIdContext::show()
{
    if (!config->tp_appid_path.empty())
        LogMessage("    3rd Party Dir: %s\n", config->tp_appid_path.c_str());
}

void AppIdContext::display_port_config()
{
    bool first = true;

    for ( auto& i : tcp_port_only )
        if (tcp_port_only[i])
        {
            if (first)
            {
                LogMessage("    TCP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, tcp_port_only[i]);
        }

    first = true;
    for ( auto& i : udp_port_only )
        if (udp_port_only[i])
        {
            if (first)
            {
                LogMessage("    UDP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, udp_port_only[i]);
        }
}

