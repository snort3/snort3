/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// arp_module.cc author Russ Combs <rucombs@cisco.com>

#include "arp_module.h"

static const char* mod_name = "arp_spoof";

#define ARPSPOOF_UNICAST_ARP_REQUEST_STR \
    "(arp_spoof) Unicast ARP request"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR \
    "(arp_spoof) Ethernet/ARP Mismatch request for Source"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR \
    "(arp_spoof) Ethernet/ARP Mismatch request for Destination"
#define ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR \
    "(arp_spoof) Attempted ARP cache overwrite attack"

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

static const Parameter arp_spoof_params[] =
{
    { "unicast", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "hosts", Parameter::PT_LIST, arp_spoof_hosts_params, nullptr,
      "help" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap arp_spoof_rules[] =
{
    { ARPSPOOF_UNICAST_ARP_REQUEST,
        ARPSPOOF_UNICAST_ARP_REQUEST_STR },

    { ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC,
        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR },

    { ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST,
        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR },

    { ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK,
        ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// arp_spoof module
//-------------------------------------------------------------------------

ArpSpoofModule::ArpSpoofModule() : 
    Module(mod_name, arp_spoof_params)
{
    config = new ArpSpoofConfig;

    config->check_unicast_arp = false;
    config->check_overwrite = false;
}

ArpSpoofModule::~ArpSpoofModule()
{
    if ( config )
        delete config;
}

const RuleMap* ArpSpoofModule::get_rules() const
{ return arp_spoof_rules; }

ProfileStats* ArpSpoofModule::get_profile() const
{ return &arpPerfStats; }

bool ArpSpoofModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("unicast") )
        config->check_unicast_arp = v.get_bool();

    else if ( v.is("ip") )
        host.ipv4_addr = v.get_ip4();

    else if ( v.is("mac") )
        v.get_mac(host.mac_addr);

    else
        return false;

    return true;
}

bool ArpSpoofModule::begin(const char*, int, SnortConfig*)
{
    memset(&host, 0, sizeof(host));
    return true;
}

bool ArpSpoofModule::end(const char*, int idx, SnortConfig*)
{
    if ( idx )
        config->ipmel.push_back(host);
    else
        config->check_overwrite = config->ipmel.size() > 0;

    return true;
}

const char** ArpSpoofModule::get_pegs() const
{ return simple_pegs; }

PegCount* ArpSpoofModule::get_counts() const
{ return (PegCount*)&asstats; }


