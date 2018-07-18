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
// codec_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codec_api.h"

#include "framework/codec.h"
#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* cd_ipv4[];    // static due to dependence on fpdetect
extern const BaseApi* cd_hopopts[]; // static to ensure the symbols CheckIPV6HopOptions
                                    // and CheckIPv6ExtensionOrder the final executable.
extern const BaseApi* cd_tcp[];     // static because only file that specific functions
                                    // (symbols will be removed from final executable)

#ifdef STATIC_CODECS
extern const BaseApi* cd_ah[];
extern const BaseApi* cd_arp[];
extern const BaseApi* cd_bad_proto[];
extern const BaseApi* cd_ciscometadata[];
extern const BaseApi* cd_dstopts[];
extern const BaseApi* cd_erspan2[];
extern const BaseApi* cd_erspan3[];
extern const BaseApi* cd_esp[];
extern const BaseApi* cd_eth[];
extern const BaseApi* cd_fabricpath[];
extern const BaseApi* cd_frag[];
extern const BaseApi* cd_gre[];
extern const BaseApi* cd_gtp[];
extern const BaseApi* cd_icmp4[];
extern const BaseApi* cd_icmp4_ip[];
extern const BaseApi* cd_icmp6[];
extern const BaseApi* cd_icmp6_ip[];
extern const BaseApi* cd_ipv6[];
extern const BaseApi* cd_igmp[];
extern const BaseApi* cd_llc[];
extern const BaseApi* cd_mobility[];
extern const BaseApi* cd_mpls[];
extern const BaseApi* cd_no_next[];
extern const BaseApi* cd_pgm[];
extern const BaseApi* cd_pppencap[];
extern const BaseApi* cd_pppoepkt[];
extern const BaseApi* cd_raw[];
extern const BaseApi* cd_routing[];
extern const BaseApi* cd_teredo[];
extern const BaseApi* cd_transbridge[];
extern const BaseApi* cd_udp[];
extern const BaseApi* cd_user[];
extern const BaseApi* cd_vlan[];
#endif

void load_codecs()
{
    PluginManager::load_plugins(cd_ipv4);
    PluginManager::load_plugins(cd_tcp);
    PluginManager::load_plugins(cd_hopopts);

#ifdef STATIC_CODECS
    PluginManager::load_plugins(cd_ah);
    PluginManager::load_plugins(cd_arp);
    PluginManager::load_plugins(cd_bad_proto);
    PluginManager::load_plugins(cd_ciscometadata);
    PluginManager::load_plugins(cd_dstopts);
    PluginManager::load_plugins(cd_erspan2);
    PluginManager::load_plugins(cd_erspan3);
    PluginManager::load_plugins(cd_esp);
    PluginManager::load_plugins(cd_eth);
    PluginManager::load_plugins(cd_fabricpath);
    PluginManager::load_plugins(cd_frag);
    PluginManager::load_plugins(cd_gre);
    PluginManager::load_plugins(cd_gtp);
    PluginManager::load_plugins(cd_icmp4);
    PluginManager::load_plugins(cd_icmp4_ip);
    PluginManager::load_plugins(cd_icmp6);
    PluginManager::load_plugins(cd_icmp6_ip);
    PluginManager::load_plugins(cd_ipv6);
    PluginManager::load_plugins(cd_igmp);
    PluginManager::load_plugins(cd_llc);
    PluginManager::load_plugins(cd_mobility);
    PluginManager::load_plugins(cd_mpls);
    PluginManager::load_plugins(cd_no_next);
    PluginManager::load_plugins(cd_pgm);
    PluginManager::load_plugins(cd_pppencap);
    PluginManager::load_plugins(cd_pppoepkt);
    PluginManager::load_plugins(cd_raw);
    PluginManager::load_plugins(cd_routing);
    PluginManager::load_plugins(cd_teredo);
    PluginManager::load_plugins(cd_transbridge);
    PluginManager::load_plugins(cd_udp);
    PluginManager::load_plugins(cd_user);
    PluginManager::load_plugins(cd_vlan);
#endif
}

