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

// arp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "arp_module.h"

using namespace snort;

#define ARPSPOOF_UNICAST_ARP_REQUEST_STR \
    "unicast ARP request"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR \
    "ethernet/ARP mismatch request for source"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR \
    "ethernet/ARP mismatch request for destination"
#define ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR \
    "attempted ARP cache overwrite attack"

THREAD_LOCAL SimpleStats asstats;

//-------------------------------------------------------------------------
// arp_spoof stuff
//-------------------------------------------------------------------------

static const Parameter arp_spoof_hosts_params[] =
{
    { "ip", Parameter::PT_IP4, nullptr, nullptr,
      "host ip address" },

    { "mac", Parameter::PT_MAC, nullptr, nullptr,
      "host mac address" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "hosts", Parameter::PT_LIST, arp_spoof_hosts_params, nullptr,
      "configure ARP cache overwrite attacks" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap s_rules[] =
{
    { ARPSPOOF_UNICAST_ARP_REQUEST, ARPSPOOF_UNICAST_ARP_REQUEST_STR },
    { ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC, ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR },
    { ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST, ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR },
    { ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK, ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// arp_spoof module
//-------------------------------------------------------------------------

ArpSpoofModule::ArpSpoofModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

ArpSpoofModule::~ArpSpoofModule()
{
    if ( config )
        delete config;
}

const RuleMap* ArpSpoofModule::get_rules() const
{ return s_rules; }

ProfileStats* ArpSpoofModule::get_profile() const
{ return &arpPerfStats; }

bool ArpSpoofModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ip") )
        host.ipv4_addr = v.get_ip4();

    else if ( v.is("mac") )
        v.get_mac(host.mac_addr);

    else
        return false;

    return true;
}

ArpSpoofConfig* ArpSpoofModule::get_config()
{
    ArpSpoofConfig* temp = config;
    config = nullptr;
    return temp;
}

bool ArpSpoofModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
    {
        config = new ArpSpoofConfig;
        config->check_overwrite = false;
    }
    memset(&host, 0, sizeof(host));
    return true;
}

bool ArpSpoofModule::end(const char*, int idx, SnortConfig*)
{
    if ( idx )
        config->ipmel.push_back(host);
    else
        config->check_overwrite = !config->ipmel.empty();

    return true;
}

const PegInfo* ArpSpoofModule::get_pegs() const
{ return snort::simple_pegs; }

PegCount* ArpSpoofModule::get_counts() const
{ return (PegCount*)&asstats; }

