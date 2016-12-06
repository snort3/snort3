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

#include "appid_module.h"

#include <string>

#include "log/messages.h"
#include "profiler/profiler.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

using namespace std;

//-------------------------------------------------------------------------
// appid module
//-------------------------------------------------------------------------

unsigned long app_id_ignored_packet_count = 0;

THREAD_LOCAL ProfileStats appidPerfStats;

// FIXIT-M define and implement a flexible solution for maintaining protocol specific stats
const PegInfo appid_pegs[] =
{
    { "packets", "count of packets received by appid inspector" },
    { "processed packets", "count of packets processed by appid inspector" },
    { "ignored packets", "count of packets ignored by appid inspector" },
    { "aim clients", "count of aim clients discovered by appid" },
    { "battlefield flows", "count of battle field flows discovered by appid" },
    { "bgp flows", "count of bgp flows discovered by appid" },
    { "bit clients", "count of bittorrent clients discovered by appid" },
    { "bit flows", "count of bittorrent flows discovered by appid" },
    { "bittracker clients", "count of bittorrent tracker clients discovered by appid" },
    { "bootp flows", "count of bootp flows discovered by appid" },
    { "dcerpc tcp flows", "count of dce rpc flows over tcp discovered by appid" },
    { "dcerpc udp flows", "count of dce rpc flows over udp discovered by appid" },
    { "direct connect flows", "count of direct connect flows discovered by appid" },
    { "dns tcp flows", "count of dns flows over tcp discovered by appid" },
    { "dns udp flows", "count of dns flows over udp discovered by appid" },
    { "ftp flows", "count of ftp flows discovered by appid" },
    { "ftps flows", "count of ftps flows discovered by appid" },
    { "http flows", "count of http flows discovered by appid" },
    { "imap flows", "count of imap service flows discovered by appid" },
    { "imaps flows", "count of imap TLS service flows discovered by appid" },
    { "irc flows", "count of irc service flows discovered by appid" },
    { "kerberos clients", "count of kerberos clients discovered by appid" },
    { "kerberos flows", "count of kerberos service flows discovered by appid" },
    { "kerberos users", "count of kerberos users discovered by appid" },
    { "lpr flows", "count of lpr service flows discovered by appid" },
    { "mdns flows", "count of mdns service flows discovered by appid" },
    { "msn clients", "count of msn clients discovered by appid" },
    { "mysql flows", "count of mysql service flows discovered by appid" },
    { "netbios dgm flows", "count of netbios-dgm service flows discovered by appid" },
    { "netbios ns flows", "count of netbios-ns service flows discovered by appid" },
    { "netbios ssn flows", "count of netbios-ssn service flows discovered by appid" },
    { "nntp flows", "count of nntp flows discovered by appid" },
    { "ntp flows", "count of ntp flows discovered by appid" },
    { "pop flows", "count of pop service flows discovered by appid" },
    { "radius flows", "count of radius flows discovered by appid" },
    { "rexec flows", "count of rexec flows discovered by appid" },
    { "rfb flows", "count of rfb flows discovered by appid" },
    { "rlogin flows", "count of rlogin flows discovered by appid" },
    { "rpc flows", "count of rpc flows discovered by appid" },
    { "rshell flows", "count of rshell flows discovered by appid" },
    { "rsync flows", "count of rsync service flows discovered by appid" },
    { "rtmp flows", "count of rtmp flows discovered by appid" },
    { "rtp clients", "count of rtp clients discovered by appid" },
    { "sip clients", "count of SIP clients discovered by appid" },
    { "sip flows", "count of SIP flows discovered by appid" },
    { "smtp aol clients", "count of AOL smtp clients discovered by appid" },
    { "smtp applemail clients", "count of Apple Mail smtp clients discovered by appid" },
    { "smtp eudora clients", "count of Eudora smtp clients discovered by appid" },
    { "smtp eudora pro clients", "count of Eudora Pro smtp clients discovered by appid" },
    { "smtp evolution clients", "count of Evolution smtp clients discovered by appid" },
    { "smtp kmail clients", "count of KMail smtp clients discovered by appid" },
    { "smtp lotus notes clients", "count of Lotus Notes smtp clients discovered by appid" },
    { "smtp microsoft outlook clients", "count of Microsoft Outlook smtp clients discovered by appid" },
    { "smtp microsoft outlook express clients", "count of Microsoft Outlook Express smtp clients discovered by appid" },
    { "smtp microsoft outlook imo clients", "count of Microsoft Outlook IMO smtp clients discovered by appid" },
    { "smtp mutt clients", "count of Mutt smtp clients discovered by appid" },
    { "smtp thunderbird clients", "count of Thunderbird smtp clients discovered by appid" },
    { "smtp flows", "count of smtp flows discovered by appid" },
    { "smtps flows", "count of smtps flows discovered by appid" },
    { "snmp flows", "count of snmp flows discovered by appid" },
    { "ssh clients", "count of ssh clients discovered by appid" },
    { "ssh flows", "count of ssh flows discovered by appid" },
    { "ssl flows", "count of ssl flows discovered by appid" },
    { "telnet flows", "count of telnet flows discovered by appid" },
    { "tftp flows", "count of tftp flows discovered by appid" },
    { "timbuktu flows", "count of timbuktu flows discovered by appid" },
    { "tns clients", "count of tns clients discovered by appid" },
    { "tns flows", "count of tns flows discovered by appid" },
    { "vnc clients", "count of vnc clients discovered by appid" },
    { "yahoo messenger clients", "count of Yahoo Messenger clients discovered by appid" },
    { nullptr, nullptr }
};

static const Parameter session_log_filter[] =
{
    {"src_ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
            "source ip address in CIDR format" },
    {  "dst_ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
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
    { "conf", Parameter::PT_STRING, nullptr, nullptr,
      "RNA configuration file" },
    { "memcap", Parameter::PT_INT, "1048576:3221225472", "268435456",
      "time period for collecting and logging AppId statistics" },
    { "log_stats", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of AppId statistics" },
    { "app_stats_period", Parameter::PT_INT, "0:", "300",
      "time period for collecting and logging AppId statistics" },
    { "app_stats_rollover_size", Parameter::PT_INT, "0:", "20971520",
      "max file size for AppId stats before rolling over the log file" },
    { "app_stats_rollover_time", Parameter::PT_INT, "0:", "86400",
      "max time period for collection AppId stats before rolling over the log file" },
    { "app_detector_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load AppId detectors from" },
    { "instance_id", Parameter::PT_INT, "0:", "0",
      "instance id - need more details for what this is" },
    { "debug", Parameter::PT_BOOL, nullptr, "false",
      "enable AppId debug logging" },
    { "dump_ports", Parameter::PT_BOOL, nullptr, "false",
      "enable dump of AppId port information" },
    { "thirdparty_appid_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load thirdparty AppId detectors from" },
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
    if ( v.is("conf") )
        config->conf_file = snort_strdup(v.get_string());
    else if ( v.is("memcap") )
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
        ParseWarning(WARN_CONF,"no app_detector_dir present.  No support for AppId in rules.\n");
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

