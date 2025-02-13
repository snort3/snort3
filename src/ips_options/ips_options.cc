//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// ips_options.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_options.h"

#include "managers/plugin_manager.h"

using namespace snort;

// these have various dependencies:
extern const BaseApi* ips_detection_filter[]; // perf stats 
extern const BaseApi* ips_flowbits[];         // public methods like flowbits_setter
extern const BaseApi* ips_pcre[];             // FIXIT-L called directly from parser
extern const BaseApi* ips_replace[];          // needs snort::SFDAQ::can_replace
extern const BaseApi* ips_so[];               // needs SO manager
extern const BaseApi* ips_vba_data[];         // FIXIT-L some trace dependency

#ifdef STATIC_IPS_OPTIONS
extern const BaseApi* ips_ack[];
extern const BaseApi* ips_base64[];
extern const BaseApi* ips_ber_data[];
extern const BaseApi* ips_ber_skip[];
extern const BaseApi* ips_bufferlen[];
extern const BaseApi* ips_byte_extract[];
extern const BaseApi* ips_byte_jump[];
extern const BaseApi* ips_byte_math[];
extern const BaseApi* ips_byte_test[];
extern const BaseApi* ips_classtype[];
extern const BaseApi* ips_content[];
extern const BaseApi* ips_cvs[];
extern const BaseApi* ips_dsize[];
extern const BaseApi* ips_enable[];
extern const BaseApi* ips_file_data[];
extern const BaseApi* ips_file_meta[];
extern const BaseApi* ips_file_type[];
extern const BaseApi* ips_flags[];
extern const BaseApi* ips_flow[];
extern const BaseApi* ips_fragbits[];
extern const BaseApi* ips_fragoffset[];
extern const BaseApi* ips_gid[];
extern const BaseApi* ips_hash[];
extern const BaseApi* ips_icmp_id[];
extern const BaseApi* ips_icmp_seq[];
extern const BaseApi* ips_icode[];
extern const BaseApi* ips_id[];
extern const BaseApi* ips_ipopts[];
extern const BaseApi* ips_ip_proto[];
extern const BaseApi* ips_isdataat[];
extern const BaseApi* ips_itype[];
extern const BaseApi* ips_js_data[];
extern const BaseApi* ips_metadata[];
extern const BaseApi* ips_msg[];
extern const BaseApi* ips_pkt_data[];
extern const BaseApi* ips_priority[];
extern const BaseApi* ips_raw_data[];
extern const BaseApi* ips_reference[];
extern const BaseApi* ips_rem[];
extern const BaseApi* ips_rev[];
extern const BaseApi* ips_rpc[];
extern const BaseApi* ips_seq[];
extern const BaseApi* ips_service[];
extern const BaseApi* ips_sid[];
extern const BaseApi* ips_soid[];
extern const BaseApi* ips_target[];
extern const BaseApi* ips_tag[];
extern const BaseApi* ips_tos[];
extern const BaseApi* ips_ttl[];
extern const BaseApi* ips_window[];

#ifdef HAVE_HYPERSCAN
extern const BaseApi* ips_regex[];
extern const BaseApi* ips_sd_pattern[];
#endif
#endif

void load_ips_options()
{
    PluginManager::load_plugins(ips_detection_filter);
    PluginManager::load_plugins(ips_flowbits);
    PluginManager::load_plugins(ips_pcre);
    PluginManager::load_plugins(ips_replace);
    PluginManager::load_plugins(ips_so);
    PluginManager::load_plugins(ips_vba_data);

#ifdef STATIC_IPS_OPTIONS
    PluginManager::load_plugins(ips_content);
    PluginManager::load_plugins(ips_ack);
    PluginManager::load_plugins(ips_base64);
    PluginManager::load_plugins(ips_ber_data);
    PluginManager::load_plugins(ips_ber_skip);
    PluginManager::load_plugins(ips_bufferlen);
    PluginManager::load_plugins(ips_byte_extract);
    PluginManager::load_plugins(ips_byte_jump);
    PluginManager::load_plugins(ips_byte_math);
    PluginManager::load_plugins(ips_byte_test);
    PluginManager::load_plugins(ips_classtype);
    PluginManager::load_plugins(ips_cvs);
    PluginManager::load_plugins(ips_dsize);
    PluginManager::load_plugins(ips_enable);
    PluginManager::load_plugins(ips_file_data);
    PluginManager::load_plugins(ips_file_meta);
    PluginManager::load_plugins(ips_file_type);
    PluginManager::load_plugins(ips_flags);
    PluginManager::load_plugins(ips_flow);
    PluginManager::load_plugins(ips_fragbits);
    PluginManager::load_plugins(ips_fragoffset);
    PluginManager::load_plugins(ips_gid);
    PluginManager::load_plugins(ips_hash);
    PluginManager::load_plugins(ips_icmp_id);
    PluginManager::load_plugins(ips_icmp_seq);
    PluginManager::load_plugins(ips_icode);
    PluginManager::load_plugins(ips_id);
    PluginManager::load_plugins(ips_ipopts);
    PluginManager::load_plugins(ips_ip_proto);
    PluginManager::load_plugins(ips_isdataat);
    PluginManager::load_plugins(ips_itype);
    PluginManager::load_plugins(ips_js_data);
    PluginManager::load_plugins(ips_metadata);
    PluginManager::load_plugins(ips_msg);
    PluginManager::load_plugins(ips_pkt_data);
    PluginManager::load_plugins(ips_priority);
    PluginManager::load_plugins(ips_raw_data);
    PluginManager::load_plugins(ips_reference);
    PluginManager::load_plugins(ips_rem);
    PluginManager::load_plugins(ips_rev);
    PluginManager::load_plugins(ips_rpc);
    PluginManager::load_plugins(ips_seq);
    PluginManager::load_plugins(ips_service);
    PluginManager::load_plugins(ips_sid);
    PluginManager::load_plugins(ips_soid);
    PluginManager::load_plugins(ips_target);
    PluginManager::load_plugins(ips_tag);
    PluginManager::load_plugins(ips_tos);
    PluginManager::load_plugins(ips_ttl);
    PluginManager::load_plugins(ips_window);
#ifdef HAVE_HYPERSCAN
    PluginManager::load_plugins(ips_regex);
    PluginManager::load_plugins(ips_sd_pattern);
#endif
#endif
}

