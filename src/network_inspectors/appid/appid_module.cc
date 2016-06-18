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

#include <string>

#include "appid_module.h"
#include "profiler/profiler.h"
#include "utils/util.h"

using namespace std;

//-------------------------------------------------------------------------
// appid module
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats appidPerfStats;

// FIXIT-M: define and implement a flexible solution for maintaining protocol specific stats
const PegInfo appid_pegs[] =
{
    { "packets", "count of packets processed by appid" },
    { "dns_udp_flows", "count of dns flows over udp discovered by appid" },
    { "dns_tcp_flows", "count of dns flows over tcp discovered by appid" },
    { "ftp_flows", "count of ftp flows discovered by appid" },
    { "ftps_flows", "count of ftps flows discovered by appid" },
    { "smtp_flows", "count of smtp flows discovered by appid" },
    { "smtps_flows", "count of smtps flows discovered by appid" },
    { "ssl_flows", "count of ssl flows discovered by appid" },
    { "telnet_flows", "count of telnet flows discovered by appid" },
    { nullptr, nullptr }
};

THREAD_LOCAL AppIdStats appid_stats;

static const Parameter s_params[] =
{
    { "conf", Parameter::PT_STRING, nullptr, nullptr,
      "RNA configuration file" },
    { "memcap", Parameter::PT_INT, "1048576:3221225472", "268435456",
      "time period for collecting and logging AppId statistics" },
    { "app_stats_filename", Parameter::PT_STRING, nullptr, nullptr,
      "Filename for logging AppId statistics" },
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

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//  FIXIT-M: Add appid_rules back in once we start using it.
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
    else if ( v.is("app_stats_filename") )
        config->app_stats_filename = snort_strdup(v.get_string());
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

