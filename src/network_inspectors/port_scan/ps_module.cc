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

// ps_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ps_module.h"

#include <cassert>

using namespace snort;

//-------------------------------------------------------------------------
// port_scan params
//-------------------------------------------------------------------------

// order of protos and scans must match PS_* flags
#define protos \
    "tcp | udp | icmp | ip | all"

#define scan_types \
    "portscan | portsweep | decoy_portscan | distributed_portscan | all"

static const Parameter scan_params[] =
{
    { "scans", Parameter::PT_INT, "0:", "100",
      "scan attempts" },

    { "rejects", Parameter::PT_INT, "0:", "15",
      "scan attempts with negative response" },

    { "nets", Parameter::PT_INT, "0:", "25",
      "number of times address changed from prior attempt" },

    { "ports", Parameter::PT_INT, "0:", "25",
      "number of times port (or proto) changed from prior attempt" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ps_params[] =
{
    { "memcap", Parameter::PT_INT, "1:", "1048576",
      "maximum tracker memory in bytes" },

    { "protos", Parameter::PT_MULTI, protos, "all",
      "choose the protocols to monitor" },

    { "scan_types", Parameter::PT_MULTI, scan_types, "all",
      "choose type of scans to look for" },

    { "watch_ip", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to watch" },

    { "ignore_scanners", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to ignore if the source of scan alerts" },

    { "ignore_scanned", Parameter::PT_STRING, nullptr, nullptr,
      "list of CIDRs with optional ports to ignore if the destination of scan alerts" },

    { "alert_all", Parameter::PT_BOOL, nullptr, "false",
      "alert on all events over threshold within window if true; else alert on first only" },

    { "include_midstream", Parameter::PT_BOOL, nullptr, "false",
      "list of CIDRs with optional ports" },

    { "tcp_ports", Parameter::PT_TABLE, scan_params, nullptr,
      "TCP port scan configuration (one-to-one)" },

    { "tcp_decoy", Parameter::PT_TABLE, scan_params, nullptr,
      "TCP decoy scan configuration (one-to-one decoy)" },

    { "tcp_sweep", Parameter::PT_TABLE, scan_params, nullptr,
      "TCP sweep scan configuration (one-to-many)" },

    { "tcp_dist", Parameter::PT_TABLE, scan_params, nullptr,
      "TCP distributed scan configuration (many-to-one)" },

    { "udp_ports", Parameter::PT_TABLE, scan_params, nullptr,
      "UDP port scan configuration (one-to-one)" },

    { "udp_decoy", Parameter::PT_TABLE, scan_params, nullptr,
      "UDP decoy scan configuration (one-to-one)" },

    { "udp_sweep", Parameter::PT_TABLE, scan_params, nullptr,
      "UDP sweep scan configuration (one-to-many)" },

    { "udp_dist", Parameter::PT_TABLE, scan_params, nullptr,
      "UDP distributed scan configuration (many-to-one)" },

    { "ip_proto", Parameter::PT_TABLE, scan_params, nullptr,
      "IP protocol scan configuration (one-to-one)" },

    { "ip_decoy", Parameter::PT_TABLE, scan_params, nullptr,
      "IP decoy scan configuration (one-to-one decoy)" },

    { "ip_sweep", Parameter::PT_TABLE, scan_params, nullptr,
      "ip sweep scan configuration (one-to-many)" },

    { "ip_dist", Parameter::PT_TABLE, scan_params, nullptr,
      "IP distributed scan configuration (many-to-one)" },

    { "icmp_sweep", Parameter::PT_TABLE, scan_params, nullptr,
      "ICMP sweep scan configuration (one-to-many)" },

    { "tcp_window", Parameter::PT_INT, "0:", "0",
      "detection interval for all TCP scans" },

    { "udp_window", Parameter::PT_INT, "0:", "0",
      "detection interval for all UDP scans" },

    { "ip_window", Parameter::PT_INT, "0:", "0",
      "detection interval for all IP scans" },

    { "icmp_window", Parameter::PT_INT, "0:", "0",
      "detection interval for all ICMP scans" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// port_scan rules
//-------------------------------------------------------------------------

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

ProfileStats* PortScanModule::get_profile() const
{ return &psPerfStats; }

const PegInfo* PortScanModule::get_pegs() const
{ return snort::simple_pegs; }

PegCount* PortScanModule::get_counts() const
{ return (PegCount*)&spstats; }

const RuleMap* PortScanModule::get_rules() const
{ return port_scan_rules; }

bool PortScanModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !config )
        config = new PortscanConfig;

    else if ( strcmp(fqn, "port_scan") )
        return false;

    return true;
}

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
bool PortScanModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if ( v.is("memcap") )
        config->memcap = v.get_long();

    else if ( v.is("protos") )
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
    else if ( v.is("alert_all") )
        config->alert_all = v.get_bool();

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
    else if ( v.is("scans") )
    {
        if ( auto p = get_alert_conf(fqn) )
            p->connection_count = v.get_long();
        else
            return false;
    }
    else if ( v.is("rejects") )
    {
        if ( auto p = get_alert_conf(fqn) )
            p->priority_count = v.get_long();
        else
            return false;
    }
    else if ( v.is("nets") )
    {
        if ( auto p = get_alert_conf(fqn) )
            p->u_ip_count = v.get_long();
        else
            return false;
    }
    else if ( v.is("ports") )
    {
        if ( auto p = get_alert_conf(fqn) )
            p->u_port_count = v.get_long();
        else
            return false;
    }
    else if ( v.is("tcp_window") )
        config->tcp_window = v.get_long();

    else if ( v.is("udp_window") )
        config->udp_window = v.get_long();

    else if ( v.is("ip_window") )
        config->ip_window = v.get_long();

    else if ( v.is("icmp_window") )
        config->icmp_window = v.get_long();

    else
        return false;

    return true;
}

PS_ALERT_CONF* PortScanModule::get_alert_conf(const char* fqn)
{
    if ( !strncmp(fqn, "port_scan.tcp_ports", 19) )
        return &config->tcp_ports;

    else if ( !strncmp(fqn, "port_scan.tcp_decoy", 19) )
        return &config->tcp_decoy;

    else if ( !strncmp(fqn, "port_scan.tcp_sweep", 19) )
        return &config->tcp_sweep;

    else if ( !strncmp(fqn, "port_scan.tcp_dist", 18) )
        return &config->tcp_dist;

    else if ( !strncmp(fqn, "port_scan.udp_ports", 19) )
        return &config->udp_ports;

    else if ( !strncmp(fqn, "port_scan.udp_decoy", 19) )
        return &config->udp_decoy;

    else if ( !strncmp(fqn, "port_scan.udp_sweep", 19) )
        return &config->udp_sweep;

    else if ( !strncmp(fqn, "port_scan.udp_dist", 18) )
        return &config->udp_dist;

    else if ( !strncmp(fqn, "port_scan.ip_proto", 18) )
        return &config->ip_proto;

    else if ( !strncmp(fqn, "port_scan.ip_decoy", 18) )
        return &config->ip_decoy;

    else if ( !strncmp(fqn, "port_scan.ip_sweep", 18) )
        return &config->ip_sweep;

    else if ( !strncmp(fqn, "port_scan.ip_dist", 17) )
        return &config->ip_dist;

    else if ( !strncmp(fqn, "port_scan.icmp_sweep", 20) )
        return &config->icmp_sweep;

    return nullptr;
}

PortscanConfig* PortScanModule::get_data()
{
    PortscanConfig* tmp = config;
    config = nullptr;
    return tmp;
}

