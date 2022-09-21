//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "helpers/discovery_filter.h"
#include "target_based/snort_protocols.h"

#include "app_info_table.h"
#include "client_plugins/client_discovery.h"
#include "client_plugins/eve_ca_patterns.h"
#include "detector_plugins/dns_patterns.h"
#include "detector_plugins/http_url_patterns.h"
#include "detector_plugins/sip_patterns.h"
#include "detector_plugins/ssl_patterns.h"
#include "host_port_app_cache.h"
#include "length_app_cache.h"
#include "lua_detector_flow_api.h"
#include "lua_detector_module.h"
#include "service_plugins/alpn_patterns.h"
#include "service_plugins/service_discovery.h"
#include "detector_plugins/ssh_patterns.h"
#include "tp_appid_module_api.h"
#include "utils/sflsq.h"

#define APP_ID_PORT_ARRAY_SIZE  65536

#define MIN_MAX_BYTES_BEFORE_SERVICE_FAIL 4096
#define MIN_MAX_PKTS_BEFORE_SERVICE_FAIL 5
#define MIN_MAX_PKT_BEFORE_SERVICE_FAIL_IGNORE_BYTES 15

enum SnortProtoIdIndex
{
    PROTO_INDEX_UNSYNCHRONIZED = 0,
    PROTO_INDEX_FTP_DATA,
    PROTO_INDEX_HTTP2,
    PROTO_INDEX_REXEC,
    PROTO_INDEX_RSH_ERROR,
    PROTO_INDEX_SNMP,
    PROTO_INDEX_SUNRPC,
    PROTO_INDEX_TFTP,
    PROTO_INDEX_SIP,
    PROTO_INDEX_SSH,

    PROTO_INDEX_MAX
};

class AppIdInspector;
class PatternClientDetector;
class PatternServiceDetector;

class AppIdConfig
{
public:
    AppIdConfig() = default;
    ~AppIdConfig();

    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    // To manually restart appid detection for an SSL-decrypted flow (single session only),
    // indicate the first packet from where the flow is decrypted (usually immediately
    // after certificate-exchange). Such manual detection is disabled by default (0).
    uint32_t first_decrypted_packet_debug = 0;
    bool log_eve_process_client_mappings = false;
#endif
    bool log_stats = false;
    uint32_t app_stats_period = 300;
    uint32_t app_stats_rollover_size = 0;
    const char* app_detector_dir = nullptr;
    std::string tp_appid_path = "";
    std::string tp_appid_config = "";
    bool tp_appid_stats_enable = false;
    bool tp_appid_config_dump = false;
    size_t memcap = 0;
    bool list_odp_detectors = false;
    bool log_all_sessions = false;
    bool enable_rna_filter = false;
    std::string rna_conf_path = "";
    SnortProtocolId snort_proto_ids[PROTO_INDEX_MAX];
    void show() const;
};

class OdpContext
{
public:
    bool dns_host_reporting = true;
    bool referred_appId_disabled = false;
    bool mdns_user_reporting = true;
    bool chp_userid_disabled = false;
    bool is_host_port_app_cache_runtime = false;
    bool check_host_port_app_cache = false;
    bool check_host_cache_unknown_ssl = false;
    bool ftp_userid_disabled = false;
    bool chp_body_collection_disabled = false;
    bool need_reinspection = false;
    uint32_t chp_body_collection_max = 0;
    uint32_t rtmp_max_packets = 15;
    uint32_t max_tp_flow_depth = 5;
    bool tp_allow_probes = false;
    uint32_t host_port_app_cache_lookup_interval = 10;
    uint32_t host_port_app_cache_lookup_range = 100000;
    bool allow_port_wildcard_host_cache = false;
    bool recheck_for_portservice_appid = false;
    uint64_t max_bytes_before_service_fail = MIN_MAX_BYTES_BEFORE_SERVICE_FAIL;
    uint16_t max_packet_before_service_fail = MIN_MAX_PKTS_BEFORE_SERVICE_FAIL;
    uint16_t max_packet_service_fail_ignore_bytes = MIN_MAX_PKT_BEFORE_SERVICE_FAIL_IGNORE_BYTES;

    OdpContext(const AppIdConfig&, snort::SnortConfig*);
    void initialize(AppIdInspector& inspector);
    void reload();

    uint32_t get_version() const
    {
        return version;
    }

    AppInfoManager& get_app_info_mgr()
    {
        return app_info_mgr;
    }

    ClientDiscovery& get_client_disco_mgr()
    {
        return client_disco_mgr;
    }

    ServiceDiscovery& get_service_disco_mgr()
    {
        return service_disco_mgr;
    }

    HostPortVal* host_port_cache_find(const snort::SfIp* ip, uint16_t port, IpProtocol proto)
    {
        return host_port_cache.find(ip, port, proto, *this);
    }

    bool host_port_cache_add(const snort::SnortConfig* sc, const snort::SfIp* ip, uint16_t port,
        IpProtocol proto, unsigned type, AppId appid)
    {
        return host_port_cache.add(sc, ip, port, proto, type, appid);
    }

    bool host_first_pkt_add(const snort::SnortConfig* sc, const snort::SfIp* ip, uint16_t port,
        IpProtocol proto, AppId protocol_appid, AppId client_appid, AppId web_appid, unsigned reinspect)
    {
        return first_pkt_cache.add_host(sc, ip, port, proto, protocol_appid, client_appid, web_appid, reinspect);
    }

    HostAppIdsVal* host_first_pkt_find(const snort::SfIp* ip, uint16_t port, IpProtocol proto)
    {
        return first_pkt_cache.find_on_first_pkt(ip, port, proto, *this);
    }

    AppId length_cache_find(const LengthKey& key)
    {
        return length_cache.find(key);
    }

    bool length_cache_add(const LengthKey& key, AppId val)
    {
        return length_cache.add(key, val);
    }

    DnsPatternMatchers& get_dns_matchers()
    {
        return dns_matchers;
    }

    HttpPatternMatchers& get_http_matchers()
    {
        return http_matchers;
    }

    EveCaPatternMatchers& get_eve_ca_matchers()
    {
        return eve_ca_matchers;
    }

    SipPatternMatchers& get_sip_matchers()
    {
        return sip_matchers;
    }

    SslPatternMatchers& get_ssl_matchers()
    {
        return ssl_matchers;
    }

    SshPatternMatchers& get_ssh_matchers()
    {
        return ssh_matchers;
    }

    PatternClientDetector& get_client_pattern_detector()
    {
        return *client_pattern_detector;
    }

    PatternServiceDetector& get_service_pattern_detector()
    {
        return *service_pattern_detector;
    }

    AlpnPatternMatchers& get_alpn_matchers()
    {
        return alpn_matchers;
    }

    void add_port_service_id(IpProtocol, uint16_t, AppId);
    void add_protocol_service_id(IpProtocol, AppId);
    AppId get_port_service_id(IpProtocol, uint16_t);
    AppId get_protocol_service_id(IpProtocol);

private:
    AppInfoManager app_info_mgr;
    ClientDiscovery client_disco_mgr;
    HostPortCache host_port_cache;
    HostPortCache first_pkt_cache;
    LengthCache length_cache;
    DnsPatternMatchers dns_matchers;
    HttpPatternMatchers http_matchers;
    EveCaPatternMatchers eve_ca_matchers;
    ServiceDiscovery service_disco_mgr;
    SipPatternMatchers sip_matchers;
    SslPatternMatchers ssl_matchers;
    SshPatternMatchers ssh_matchers;
    PatternClientDetector* client_pattern_detector;
    PatternServiceDetector* service_pattern_detector;
    AlpnPatternMatchers alpn_matchers;

    std::array<AppId, APP_ID_PORT_ARRAY_SIZE> tcp_port_only = {}; // port-only TCP services
    std::array<AppId, APP_ID_PORT_ARRAY_SIZE> udp_port_only = {}; // port-only UDP services
    std::array<AppId, 256> ip_protocol = {}; // non-TCP / UDP protocol services

    uint32_t version;
    static uint32_t next_version;
};

class OdpThreadContext
{
public:
    ~OdpThreadContext();
    void initialize(const snort::SnortConfig*, AppIdContext& ctxt, bool is_control=false,
        bool reload_odp=false);

    void set_lua_detector_mgr(LuaDetectorManager& mgr)
    {
        lua_detector_mgr = &mgr;
    }

    LuaDetectorManager& get_lua_detector_mgr() const
    {
        assert(lua_detector_mgr);
        return *lua_detector_mgr;
    }

private:
    LuaDetectorManager* lua_detector_mgr = nullptr;
};

class AppIdContext
{
public:
    AppIdContext(AppIdConfig& config) : config(config)
    { }

    ~AppIdContext()
    {
        if (discovery_filter)
            delete discovery_filter;
    }

    OdpContext& get_odp_ctxt() const
    {
        assert(odp_ctxt);
        return *odp_ctxt;
    }
    DiscoveryFilter* get_discovery_filter() const
    {
        return discovery_filter;
    }

    ThirdPartyAppIdContext* get_tp_appid_ctxt() const
    { return tp_appid_ctxt; }

    static void delete_tp_appid_ctxt()
    { delete tp_appid_ctxt; }

    void create_odp_ctxt();
    void create_tp_appid_ctxt();
    bool init_appid(snort::SnortConfig*, AppIdInspector&);
    static void pterm();
    void show() const;

    AppIdConfig& config;

private:
    DiscoveryFilter* discovery_filter = nullptr;
    static OdpContext* odp_ctxt;
    static ThirdPartyAppIdContext* tp_appid_ctxt;
};

#endif
