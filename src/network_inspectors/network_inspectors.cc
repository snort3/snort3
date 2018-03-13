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

#include "network_inspectors.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* nin_binder;
extern const BaseApi* nin_normalize;
extern const BaseApi* nin_reputation;

extern const BaseApi* nin_appid[];
extern const BaseApi* nin_port_scan[];

#ifdef STATIC_INSPECTORS
extern const BaseApi* nin_arp_spoof[];
extern const BaseApi* nin_packet_capture[];
extern const BaseApi* nin_perf_monitor[];
#endif

static const BaseApi* network_inspectors[] =
{
    nin_binder,
    nin_normalize,
    nin_reputation,
    nullptr
};

void load_network_inspectors()
{
    PluginManager::load_plugins(network_inspectors);
    PluginManager::load_plugins(nin_appid);
    PluginManager::load_plugins(nin_port_scan);

#ifdef STATIC_INSPECTORS
    PluginManager::load_plugins(nin_arp_spoof);
    PluginManager::load_plugins(nin_packet_capture);
    PluginManager::load_plugins(nin_perf_monitor);
#endif
}

