//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

// alert_ex.cc author Russ Combs <rucombs@cisco.com>

#include <iostream>

#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"

using namespace std;

static const char* s_name = "alert_ex";
static const char* s_help = "output gid:sid:rev for alerts";

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "upper", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> convert to upper/lower case" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ExModule : public Module
{
public:
    ExModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

public:
    bool upper;
};

bool ExModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("packet") )
        upper = v.get_bool();

    else
        return false;

    return true;
}

bool ExModule::begin(const char*, int, SnortConfig*)
{
    upper = true;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class ExLogger : public Logger
{
public:
    ExLogger(ExModule* m)
    { upper = m->upper; }

    void alert(Packet*, const char* msg, const Event&) override;

private:
    bool upper;
};

void ExLogger::alert(Packet*, const char* msg, const Event& e)
{
    string s = msg;

    if ( upper )
        transform(s.begin(), s.end(), s.begin(), ::toupper);
    else
        transform(s.begin(), s.end(), s.begin(), ::tolower);

    cout << e.sig_info->gid << ":";
    cout << e.sig_info->sid << ":";
    cout << e.sig_info->rev << " ";
    cout << s << endl;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ExModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* ex_ctor(SnortConfig*, Module* mod)
{
    return new ExLogger((ExModule*)mod);
}

static void ex_dtor(Logger* p)
{ delete p; }

static const LogApi ex_api =
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    ex_ctor,
    ex_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ex_api.base,
    nullptr
};

