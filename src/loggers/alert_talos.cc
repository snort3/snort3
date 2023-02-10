//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// alert_talos.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>

#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "packet_io/sfdaq.h"

using namespace snort;
using namespace std;

struct AlertLog
{
    string name;
    struct Rule
    {
        void print();
        string key;
        string msg;
        uint32_t gid;
        uint32_t sid;
        uint32_t rev;
        unsigned count;
    };
    map<string, Rule> alerts;
};

static THREAD_LOCAL AlertLog* talos_log = nullptr;

void AlertLog::Rule::print()
{
    string color, reset;

    if ( isatty(fileno(stdout)) )
    {
        reset = "\x1b[0m";

        switch (gid)
        {
        case 1:
            color = "\x1b[31m";
            break;
        case 3:
            color = "\x1b[32m";
            break;
        default:
            color = "\x1b[33m";
            break;
        }
    }

    cout << "\t" << key << " " << color
         << msg << reset << " (alerts: "
         << count << ")" << endl;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define S_NAME "alert_talos"
#define s_help "output event in Talos alert format"

class TalosModule : public Module
{
public:
    TalosModule() : Module(S_NAME, s_help, s_params) { }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class TalosLogger : public Logger
{
public:
    TalosLogger(TalosModule*) { }

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;
};

void TalosLogger::open()
{
    talos_log = new AlertLog;

    string ifname = string(SFDAQ::get_input_spec());
    size_t sep_pos = ifname.find_last_of("/\\");

    if ( sep_pos != string::npos )
        ifname = ifname.substr(sep_pos+1);

    talos_log->name = ifname;
}

void TalosLogger::close()
{
    if ( !talos_log )
        return;

    auto& alerts = talos_log->alerts;

    cout << endl << "##### " << talos_log->name << " #####" << endl;

    if ( alerts.size() == 0 )
    {
        cout << "\tNo alerts" << endl;
    }

    for ( auto& kv : alerts )
    {
        kv.second.print();
    }

    cout << "#####" << endl;

    delete talos_log;
}

void TalosLogger::alert(Packet*, const char* msg, const Event& event)
{
    auto& alerts = talos_log->alerts;
    AlertLog::Rule rule;
    stringstream key;
    string message;

    key << "["
        << event.sig_info->gid << ":"
        << event.sig_info->sid << ":"
        << event.sig_info->rev
        << "]";

    auto rule_iter = alerts.find(key.str());

    // check if rule is in alert map
    if ( rule_iter != alerts.end() )
    {
        // rule in alert map, increment count
        rule_iter->second.count += 1;
        return;
    }

    message = string(msg);

    if ( message.length() < 2 )
        return;

    // remove quotes
    message.erase(0,1);
    message.pop_back();

    rule.key = key.str();
    rule.msg = message;
    rule.gid = event.sig_info->gid;
    rule.sid = event.sig_info->sid;
    rule.rev = event.sig_info->rev;
    rule.count = 1;

    // rule not in map, add it
    alerts[key.str()] = rule;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TalosModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* talos_ctor(Module* mod)
{ return new TalosLogger((TalosModule*)mod); }

static void talos_dtor(Logger* p)
{ delete p; }

static LogApi talos_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    talos_ctor,
    talos_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_talos[] =
#endif
{
    &talos_api.base,
    nullptr
};

