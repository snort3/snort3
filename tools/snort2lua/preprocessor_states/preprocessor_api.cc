//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// preprocessor_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "preprocessor_states/preprocessor_api.h"

namespace preprocessors
{
extern const ConvertMap* appid_map;
extern const ConvertMap* arpspoof_map;
extern const ConvertMap* arpspoof_host_map;
extern const ConvertMap* bo_map;
extern const ConvertMap* dcerpc_map;
extern const ConvertMap* dcerpc_server_map;
extern const ConvertMap* dnp3_map;
extern const ConvertMap* firewall_map;
extern const ConvertMap* frag3_engine_map;
extern const ConvertMap* frag3_global_map;
extern const ConvertMap* ftptelnet_map;
extern const ConvertMap* ftptelnet_protocol_map;
extern const ConvertMap* gtp_map;
extern const ConvertMap* httpinspect_map;
extern const ConvertMap* httpinspect_server_map;
extern const ConvertMap* nap_selector_map;
extern const ConvertMap* nhttpinspect_map;
extern const ConvertMap* nhttpinspect_server_map;
extern const ConvertMap* normalizer_icmp4_map;
extern const ConvertMap* normalizer_icmp6_map;
extern const ConvertMap* normalizer_ip4_map;
extern const ConvertMap* normalizer_ip6_map;
extern const ConvertMap* normalizer_tcp_map;
extern const ConvertMap* perfmonitor_map;
extern const ConvertMap* reputation_map;
extern const ConvertMap* rpc_decode_map;
extern const ConvertMap* sip_map;
extern const ConvertMap* ssh_map;
extern const ConvertMap* ssl_map;
extern const ConvertMap* dns_map;
extern const ConvertMap* pop_map;
extern const ConvertMap* imap_map;
extern const ConvertMap* modbus_map;
extern const ConvertMap* sdf_map;
extern const ConvertMap* smtp_map;
extern const ConvertMap* sfportscan_map;
extern const ConvertMap* stream_ip_map;
extern const ConvertMap* stream_global_map;
extern const ConvertMap* stream_tcp_map;
extern const ConvertMap* stream_udp_map;

std::vector<const ConvertMap*> preprocessor_api =
{
    appid_map,
    arpspoof_map,
    arpspoof_host_map,
    bo_map,
    dcerpc_map,
    dcerpc_server_map,
    dnp3_map,
    dns_map,
    firewall_map,
    frag3_engine_map,
    frag3_global_map,
    ftptelnet_map,
    ftptelnet_protocol_map,
    gtp_map,
    imap_map,
    modbus_map,
    nap_selector_map,
    nhttpinspect_map,
    nhttpinspect_server_map,
    normalizer_icmp4_map,
    normalizer_icmp6_map,
    normalizer_ip4_map,
    normalizer_ip6_map,
    normalizer_tcp_map,
    perfmonitor_map,
    pop_map,
    reputation_map,
    rpc_decode_map,
    sdf_map,
    sfportscan_map,
    sip_map,
    smtp_map,
    ssh_map,
    ssl_map,
    stream_ip_map,
    stream_global_map,
    stream_tcp_map,
    stream_udp_map,
};

std::vector<const ConvertMap*> get_preprocessor_api()
{ return preprocessor_api; }

} // namespace preprocessors

