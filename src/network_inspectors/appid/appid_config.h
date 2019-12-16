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

// appid_config.h author Sourcefire Inc.

#ifndef APP_ID_CONFIG_H
#define APP_ID_CONFIG_H

#include <array>
#include <string>

#include "application_ids.h"
#include "framework/decode_data.h"
#include "main/snort_config.h"
#include "protocols/ipv6.h"
#include "sfip/sf_ip.h"
#include "target_based/snort_protocols.h"
#include "utils/sflsq.h"

#define APP_ID_MAX_DIRS         16
#define APP_ID_PORT_ARRAY_SIZE  65536
#define MAX_ZONES               1024

struct NetworkSet;
class AppIdInspector;
class AppInfoManager;

extern unsigned appIdPolicyId;
extern uint32_t app_id_netmasks[];

extern SnortProtocolId snortId_for_unsynchronized;
extern SnortProtocolId snortId_for_ftp_data;
extern SnortProtocolId snortId_for_http2;

struct PortExclusion
{
    int family;
    snort::ip::snort_in6_addr ip;
    snort::ip::snort_in6_addr netmask;
};

class AppIdModuleConfig
{
public:
    AppIdModuleConfig() = default;
    ~AppIdModuleConfig();

    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    // To manually restart appid detection for an SSL-decrypted flow (single session only),
    // indicate the first packet from where the flow is decrypted (usually immediately
    // after certificate-exchange). Such manual detection is disabled by default (0).
    uint32_t first_decrypted_packet_debug = 0;
#endif
    bool stats_logging_enabled = false;
    unsigned long app_stats_period = 300;
    unsigned long app_stats_rollover_size = 0;
    unsigned long app_stats_rollover_time = 0;
    const char* app_detector_dir = nullptr;
    std::string tp_appid_path = "";
    std::string tp_appid_config = "";
    bool tp_appid_stats_enable = false;
    bool tp_appid_config_dump = false;
    uint32_t instance_id = 0;
    size_t memcap = 0;
    bool debug = false;
    bool dump_ports = false;
    bool log_all_sessions = false;

    bool safe_search_enabled = true;
    bool dns_host_reporting = true;
    bool referred_appId_disabled = false;
    bool mdns_user_reporting = true;
    bool chp_userid_disabled = false;
    bool http2_detection_enabled = false;
    bool is_host_port_app_cache_runtime = false;
    bool check_host_port_app_cache = false;
    bool check_host_cache_unknown_ssl = false;
    uint32_t ftp_userid_disabled = 0;
    uint32_t chp_body_collection_disabled = 0;
    uint32_t chp_body_collection_max = 0;
    uint32_t rtmp_max_packets = 15;
    uint32_t max_tp_flow_depth = 5;
    uint32_t tp_allow_probes = 0;
    uint32_t host_port_app_cache_lookup_interval = 10;
    uint32_t host_port_app_cache_lookup_range = 100000;
    uint32_t http_response_version_enabled = 0;
    bool allow_port_wildcard_host_cache = false;
    bool recheck_for_portservice_appid = false;
};

typedef std::array<SF_LIST*, APP_ID_PORT_ARRAY_SIZE> AppIdPortExclusions;

class AppIdConfig
{
public:
    AppIdConfig(AppIdModuleConfig* config) : mod_config(config)
    { }

    bool init_appid(snort::SnortConfig*);
    static void pterm();
    void show();
    AppId get_port_service_id(IpProtocol, uint16_t port);
    AppId get_protocol_service_id(IpProtocol);

    unsigned max_service_info = 0;

    //FIXIT-L remove static when reload is supported (once flag removed)
    static std::array<AppId, APP_ID_PORT_ARRAY_SIZE> tcp_port_only;     // port-only TCP services
    static std::array<AppId, APP_ID_PORT_ARRAY_SIZE> udp_port_only;     // port-only UDP services
    static std::array<AppId, 256> ip_protocol;         // non-TCP / UDP protocol services

    SF_LIST client_app_args;                    // List of Client App arguments
    // for each potential port, an sflist of PortExclusion structs
    AppIdModuleConfig* mod_config = nullptr;
    unsigned appIdPolicyId = 53;

private:
    void read_port_detectors(const char* files);
    void display_port_config();
    // FIXIT-M: RELOAD - Remove static, once app_info_mgr cleanup is
    // removed from AppIdConfig::pterm
    static AppInfoManager& app_info_mgr;
};

#endif
