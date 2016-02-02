//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// ps_module.cc author Russ Combs <rucombs@cisco.com>

#include "ps_module.h"

//-------------------------------------------------------------------------
// port_scan tables
//-------------------------------------------------------------------------

// order of protos and scans must match PS_* flags
#define protos \
    "tcp | udp | icmp | ip | all"

#define scans \
    "portscan | portsweep | decoy_portscan | distributed_portscan | all"

static const Parameter ps_params[] =
{
    { "protos", Parameter::PT_MULTI, protos, "all",
      "choose the protocols to monitor" },

    { "scan_types", Parameter::PT_MULTI, scans, "all",
      "choose type of scans to look for" },

    { "sense_level", Parameter::PT_ENUM, "low | medium | high", "medium",
      "choose the level of detection" },

    { "watch_ip", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to watch" },

    { "ignore_scanners", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to ignore if the source of scan alerts" },

    { "ignore_scanned", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to ignore if the destination of scan alerts" },

    { "include_midstream", Parameter::PT_BOOL, nullptr, "false",
      "list of CIDRs with optional ports" },

    { "logfile", Parameter::PT_BOOL, nullptr, "false",
      "write scan events to file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap port_scan_rules[] =
{
    { PSNG_TCP_PORTSCAN, PSNG_TCP_PORTSCAN_STR },
    { PSNG_TCP_DECOY_PORTSCAN, PSNG_TCP_DECOY_PORTSCAN_STR },
    { PSNG_TCP_PORTSWEEP, PSNG_TCP_PORTSWEEP_STR },
    { PSNG_TCP_DISTRIBUTED_PORTSCAN, PSNG_TCP_DISTRIBUTED_PORTSCAN_STR },
    { PSNG_TCP_FILTERED_PORTSCAN, PSNG_TCP_FILTERED_PORTSCAN_STR },
    { PSNG_TCP_FILTERED_DECOY_PORTSCAN, PSNG_TCP_FILTERED_DECOY_PORTSCAN_STR },
    { PSNG_TCP_PORTSWEEP_FILTERED, PSNG_TCP_PORTSWEEP_FILTERED_STR },
    { PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN,
      PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN_STR },

    { PSNG_IP_PORTSCAN, PSNG_IP_PORTSCAN_STR },
    { PSNG_IP_DECOY_PORTSCAN, PSNG_IP_DECOY_PORTSCAN_STR },
    { PSNG_IP_PORTSWEEP, PSNG_IP_PORTSWEEP_STR },
    { PSNG_IP_DISTRIBUTED_PORTSCAN, PSNG_IP_DISTRIBUTED_PORTSCAN_STR },
    { PSNG_IP_FILTERED_PORTSCAN, PSNG_IP_FILTERED_PORTSCAN_STR },
    { PSNG_IP_FILTERED_DECOY_PORTSCAN, PSNG_IP_FILTERED_DECOY_PORTSCAN_STR },
    { PSNG_IP_PORTSWEEP_FILTERED, PSNG_IP_PORTSWEEP_FILTERED_STR },
    { PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN, PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN_STR },

    { PSNG_UDP_PORTSCAN, PSNG_UDP_PORTSCAN_STR },
    { PSNG_UDP_DECOY_PORTSCAN, PSNG_UDP_DECOY_PORTSCAN_STR },
    { PSNG_UDP_PORTSWEEP, PSNG_UDP_PORTSWEEP_STR },
    { PSNG_UDP_DISTRIBUTED_PORTSCAN, PSNG_UDP_DISTRIBUTED_PORTSCAN_STR },
    { PSNG_UDP_FILTERED_PORTSCAN, PSNG_UDP_FILTERED_PORTSCAN_STR },
    { PSNG_UDP_FILTERED_DECOY_PORTSCAN, PSNG_UDP_FILTERED_DECOY_PORTSCAN_STR },
    { PSNG_UDP_PORTSWEEP_FILTERED, PSNG_UDP_PORTSWEEP_FILTERED_STR },
    { PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN, PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN_STR },

    { PSNG_ICMP_PORTSWEEP, PSNG_ICMP_PORTSWEEP_STR },
    { PSNG_ICMP_PORTSWEEP_FILTERED, PSNG_ICMP_PORTSWEEP_FILTERED_STR },

    { PSNG_OPEN_PORT, PSNG_OPEN_PORT_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// port_scan module
//-------------------------------------------------------------------------

PortScanModule::PortScanModule() :
    Module(PS_NAME, PS_HELP, ps_params)
{
    config = nullptr;
}

PortScanModule::~PortScanModule()
{
    if ( config )
        delete config;
}

const RuleMap* PortScanModule::get_rules() const
{ return port_scan_rules; }

//-------------------------------------------------------------------------
// FIXIT-L ipset_parse() format must be changed to remove comma
// separators between tokens which means using something other than
// space between CIDR and port.  the current format is:
// CIDR[ ports][,CIDR[ ports]]*
// ports is either a single port or a range (num-num)
// note that the current code has a parsing bug:
// 3.4.5.6/16 7 works but 3.4.5.6 7 does not.
// a possible new format is:
// CIDR[#ports][ CIDR[#ports]]*
// also note that classic Snort address lists appear to be allowed which
// will cause problems with Lua syntax if [[ and ]] are present.  must be
// [ [ and ] ].
// consult RFC 5952 for ideas.
//-------------------------------------------------------------------------
bool PortScanModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("protos") )
    {
        unsigned u = v.get_long();
        if ( u & (PS_PROTO_ALL+1) )
            u = PS_PROTO_ALL;
        config->detect_scans = u;
    }
    else if ( v.is("scan_types") )
    {
        unsigned u = v.get_long();
        if ( u & (PS_TYPE_ALL+1) )
            u = PS_TYPE_ALL;
        config->detect_scan_type = u;
    }
    else if ( v.is("sense_level") )
        config->sense_level = v.get_long() + 1;

    else if ( v.is("include_midstream") )
        config->include_midstream = v.get_bool();

    else if ( v.is("watch_ip") )
    {
        IPSET*& ips = config->watch_ip;
        ips = ipset_new();
        if ( !ips || ipset_parse(ips, v.get_string()) )
            return false;
    }
    else if ( v.is("ignore_scanners") )
    {
        IPSET*& ips = config->ignore_scanners;
        ips = ipset_new();
        if ( !ips || ipset_parse(ips, v.get_string()) )
            return false;
    }
    else if ( v.is("ignore_scanned") )
    {
        IPSET*& ips = config->ignore_scanned;
        ips = ipset_new();
        if ( !ips || ipset_parse(ips, v.get_string()) )
            return false;
    }
    else if ( v.is("logfile") )
        config->logfile = v.get_bool();

    else
        return false;

    return true;
}

bool PortScanModule::begin(const char*, int, SnortConfig*)
{
    config = new PortscanConfig;
    return true;
}

PortscanConfig* PortScanModule::get_data()
{
    PortscanConfig* tmp = config;
    config = nullptr;
    return tmp;
}

//-------------------------------------------------------------------------
// port_scan module
//-------------------------------------------------------------------------

static const Parameter psg_params[] =
{
    { "memcap", Parameter::PT_INT, "1:", "1048576",
      "maximum tracker memory" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

PortScanGlobalModule::PortScanGlobalModule() :
    Module(PSG_NAME, PSG_HELP, psg_params)
{
    common = nullptr;
}

PortScanGlobalModule::~PortScanGlobalModule()
{
    if ( common )
        delete common;
}

ProfileStats* PortScanGlobalModule::get_profile() const
{ return &psPerfStats; }

bool PortScanGlobalModule::begin(const char*, int, SnortConfig*)
{
    common = new PsCommon;
    common->memcap = 1048576;
    return true;
}

bool PortScanGlobalModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("memcap") )
        common->memcap = v.get_long();

    else
        return false;

    return true;
}

PsCommon* PortScanGlobalModule::get_data()
{
    PsCommon* tmp = common;
    common = nullptr;
    return tmp;
}

const PegInfo* PortScanGlobalModule::get_pegs() const
{ return simple_pegs; }

PegCount* PortScanGlobalModule::get_counts() const
{ return (PegCount*)&spstats; }

