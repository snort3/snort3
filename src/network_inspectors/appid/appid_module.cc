//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// appid_module.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_module.h"

#include "log/messages.h"
#include "profiler/profiler.h"

using namespace std;

//-------------------------------------------------------------------------
// appid module
//-------------------------------------------------------------------------

unsigned long app_id_ignored_packet_count = 0;

THREAD_LOCAL ProfileStats appidPerfStats;

// FIXIT-M define and implement a flexible solution for maintaining protocol specific stats
const PegInfo appid_pegs[] =
{
    { "packets", "count of packets received" },
    { "processed packets", "count of packets processed" },
    { "ignored packets", "count of packets ignored" },
    { "aim clients", "count of aim clients discovered" },
    { "battlefield flows", "count of battle field flows discovered" },
    { "bgp flows", "count of bgp flows discovered" },
    { "bit clients", "count of bittorrent clients discovered" },
    { "bit flows", "count of bittorrent flows discovered" },
    { "bittracker clients", "count of bittorrent tracker clients discovered" },
    { "bootp flows", "count of bootp flows discovered" },
    { "dcerpc tcp flows", "count of dce rpc flows over tcp discovered" },
    { "dcerpc udp flows", "count of dce rpc flows over udp discovered" },
    { "direct connect flows", "count of direct connect flows discovered" },
    { "dns tcp flows", "count of dns flows over tcp discovered" },
    { "dns udp flows", "count of dns flows over udp discovered" },
    { "ftp flows", "count of ftp flows discovered" },
    { "ftps flows", "count of ftps flows discovered" },
    { "http flows", "count of http flows discovered" },
    { "imap flows", "count of imap service flows discovered" },
    { "imaps flows", "count of imap TLS service flows discovered" },
    { "irc flows", "count of irc service flows discovered" },
    { "kerberos clients", "count of kerberos clients discovered" },
    { "kerberos flows", "count of kerberos service flows discovered" },
    { "kerberos users", "count of kerberos users discovered" },
    { "lpr flows", "count of lpr service flows discovered" },
    { "mdns flows", "count of mdns service flows discovered" },
    { "msn clients", "count of msn clients discovered" },
    { "mysql flows", "count of mysql service flows discovered" },
    { "netbios dgm flows", "count of netbios-dgm service flows discovered" },
    { "netbios ns flows", "count of netbios-ns service flows discovered" },
    { "netbios ssn flows", "count of netbios-ssn service flows discovered" },
    { "nntp flows", "count of nntp flows discovered" },
    { "ntp flows", "count of ntp flows discovered" },
    { "pop flows", "count of pop service flows discovered" },
    { "radius flows", "count of radius flows discovered" },
    { "rexec flows", "count of rexec flows discovered" },
    { "rfb flows", "count of rfb flows discovered" },
    { "rlogin flows", "count of rlogin flows discovered" },
    { "rpc flows", "count of rpc flows discovered" },
    { "rshell flows", "count of rshell flows discovered" },
    { "rsync flows", "count of rsync service flows discovered" },
    { "rtmp flows", "count of rtmp flows discovered" },
    { "rtp clients", "count of rtp clients discovered" },
    { "sip clients", "count of SIP clients discovered" },
    { "sip flows", "count of SIP flows discovered" },
    { "smtp aol clients", "count of AOL smtp clients discovered" },
    { "smtp applemail clients", "count of Apple Mail smtp clients discovered" },
    { "smtp eudora clients", "count of Eudora smtp clients discovered" },
    { "smtp eudora pro clients", "count of Eudora Pro smtp clients discovered" },
    { "smtp evolution clients", "count of Evolution smtp clients discovered" },
    { "smtp kmail clients", "count of KMail smtp clients discovered" },
    { "smtp lotus notes clients", "count of Lotus Notes smtp clients discovered" },
    { "smtp microsoft outlook clients", "count of Microsoft Outlook smtp clients discovered" },
    { "smtp microsoft outlook express clients",
      "count of Microsoft Outlook Express smtp clients discovered" },
    { "smtp microsoft outlook imo clients",
      "count of Microsoft Outlook IMO smtp clients discovered" },
    { "smtp mutt clients", "count of Mutt smtp clients discovered" },
    { "smtp thunderbird clients", "count of Thunderbird smtp clients discovered" },
    { "smtp flows", "count of smtp flows discovered" },
    { "smtps flows", "count of smtps flows discovered" },
    { "snmp flows", "count of snmp flows discovered" },
    { "ssh clients", "count of ssh clients discovered" },
    { "ssh flows", "count of ssh flows discovered" },
    { "ssl flows", "count of ssl flows discovered" },
    { "telnet flows", "count of telnet flows discovered" },
    { "tftp flows", "count of tftp flows discovered" },
    { "timbuktu flows", "count of timbuktu flows discovered" },
    { "tns clients", "count of tns clients discovered" },
    { "tns flows", "count of tns flows discovered" },
    { "vnc clients", "count of vnc clients discovered" },
    { "yahoo messenger clients", "count of Yahoo Messenger clients discovered" },
    { nullptr, nullptr }
};

static const Parameter session_log_filter[] =
{
    { "src_ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
      "source ip address in CIDR format" },
    { "dst_ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
      "destination ip address in CIDR format" },
    { "src_port", Parameter::PT_PORT, "1:", nullptr, "source port" },
    { "dst_port", Parameter::PT_PORT, "1:", nullptr, "destination port" },
    { "protocol", Parameter::PT_STRING, nullptr, nullptr,"ip protocol"},
    { "log_all_sessions", Parameter::PT_BOOL, nullptr, "false",
      "enable logging for all appid sessions" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
#if USE_RNA_CONFIG
    { "conf", Parameter::PT_STRING, nullptr, nullptr,
      "RNA configuration file" },  // FIXIT-L eliminate reference to "RNA"
#endif
    { "memcap", Parameter::PT_INT, "0:", "0",
      "disregard - not implemented" },  // FIXIT-M implement or delete appid.memcap
    { "log_stats", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of appid statistics" },
    { "app_stats_period", Parameter::PT_INT, "0:", "300",
      "time period for collecting and logging appid statistics" },
    { "app_stats_rollover_size", Parameter::PT_INT, "0:", "20971520",
      "max file size for appid stats before rolling over the log file" },
    { "app_stats_rollover_time", Parameter::PT_INT, "0:", "86400",
      "max time period for collection appid stats before rolling over the log file" },
    { "app_detector_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load appid detectors from" },
    { "instance_id", Parameter::PT_INT, "0:", "0",
      "instance id - need more details for what this is" },
    { "debug", Parameter::PT_BOOL, nullptr, "false",
      "enable appid debug logging" },
    { "dump_ports", Parameter::PT_BOOL, nullptr, "false",
      "enable dump of appid port information" },
#ifdef REMOVED_WHILE_NOT_IN_USE
    { "thirdparty_appid_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load thirdparty appid detectors from" },
#endif
    { "session_log_filter", Parameter::PT_TABLE, session_log_filter, nullptr,
      "session log filter options" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//  FIXIT-M Add appid_rules back in once we start using it.
#ifdef REMOVED_WHILE_NOT_IN_USE
static const RuleMap appid_rules[] =
{
    { 0 /* rule id */, "description" },
    { 0, nullptr }
};
#endif

AppIdModule::AppIdModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

AppIdModule::~AppIdModule()
{
}

ProfileStats* AppIdModule::get_profile() const
{
    return &appidPerfStats;
}

const AppIdModuleConfig* AppIdModule::get_data()
{
    AppIdModuleConfig* temp = config;
    config = nullptr;
    return temp;
}

bool AppIdModule::set(const char*, Value& v, SnortConfig*)
{
#if USE_RNA_CONFIG
    if ( v.is("conf") )
        config->conf_file = snort_strdup(v.get_string());
    else
#endif
    if ( v.is("memcap") )
        config->memcap = v.get_long();
    else if ( v.is("log_stats") )
        config->stats_logging_enabled = v.get_bool();
    else if ( v.is("app_stats_period") )
        config->app_stats_period = v.get_long();
    else if ( v.is("app_stats_rollover_size") )
        config->app_stats_rollover_size = v.get_long();
    else if ( v.is("app_stats_rollover_time") )
        config->app_stats_rollover_time = v.get_long();
    else if ( v.is("app_detector_dir") )
        config->app_detector_dir = snort_strdup(v.get_string());
    else if ( v.is("thirdparty_appid_dir") )
        config->thirdparty_appid_dir = snort_strdup(v.get_string());
    else if ( v.is("instance_id") )
        config->instance_id = v.get_long();
    else if ( v.is("debug") )
        config->debug = v.get_bool();
    else if ( v.is("dump_ports") )
        config->dump_ports = v.get_bool();
    else if ( v.is("session_log_filter") )
        config->session_log_filter.log_all_sessions = false;  // FIXIT-L need to implement support for all log options
    else if ( v.is("log_all_sessions") )
        config->session_log_filter.log_all_sessions = v.get_bool();
    else if (v.is("src_ip") )
        config->session_log_filter.sip.set(v.get_string());
    else if (v.is("dst_ip") )
        config->session_log_filter.dip.set(v.get_string());
    else
        return false;

    return true;
}

bool AppIdModule::begin(const char* /*fqn*/, int, SnortConfig*)
{
    if ( config )
        return false;

    config = new AppIdModuleConfig;
    return true;
}

bool AppIdModule::end(const char*, int, SnortConfig*)
{
    if ( (config == nullptr) || (config->app_detector_dir == nullptr) )
    {
        ParseWarning(WARN_CONF,"no app_detector_dir present.  No support for appid in rules.\n");
    }

    return true;
}

const PegInfo* AppIdModule::get_pegs() const
{
    return appid_pegs;
}

PegCount* AppIdModule::get_counts() const
{
    return (PegCount*)&appid_stats;
}

