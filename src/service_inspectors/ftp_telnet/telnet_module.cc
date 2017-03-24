//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// telnet_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "telnet_module.h"

#include <cassert>

using namespace std;

//-------------------------------------------------------------------------
// telnet module
//-------------------------------------------------------------------------

#define TELNET_AYT_OVERFLOW_STR                  \
    "consecutive telnet AYT commands beyond threshold"
#define TELNET_ENCRYPTED_STR                     \
    "telnet traffic encrypted"
#define TELNET_SB_NO_SE_STR                      \
    "telnet subnegotiation begin command without subnegotiation end"

static const Parameter s_params[] =
{
    { "ayt_attack_thresh", Parameter::PT_INT, "-1:", "-1",
      "alert on this number of consecutive telnet AYT commands" },

    { "check_encrypted", Parameter::PT_BOOL, nullptr, "false",
      "check for end of encryption" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted telnet and ftp" },

    { "normalize", Parameter::PT_BOOL, nullptr, "false",
      "eliminate escape sequences" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap telnet_rules[] =
{
    { TELNET_AYT_OVERFLOW, TELNET_AYT_OVERFLOW_STR },
    { TELNET_ENCRYPTED, TELNET_ENCRYPTED_STR },
    { TELNET_SB_NO_SE, TELNET_SB_NO_SE_STR },

    { 0, nullptr }
};

TelnetModule::TelnetModule() :
    Module(TEL_NAME, TEL_HELP, s_params)
{
    conf = nullptr;
}

TelnetModule::~TelnetModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* TelnetModule::get_rules() const
{ return telnet_rules; }

ProfileStats* TelnetModule::get_profile() const
{ return &telnetPerfStats; }

bool TelnetModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ayt_attack_thresh") )
        conf->ayt_threshold = v.get_long();

    else if ( v.is("check_encrypted") )
        conf->detect_encrypted = v.get_bool();

    else if ( v.is("encrypted_traffic") )
        conf->check_encrypted_data = v.get_bool();

    else if ( v.is("normalize") )
        conf->normalize = v.get_bool();

    else
        return false;

    return true;
}

TELNET_PROTO_CONF* TelnetModule::get_data()
{
    TELNET_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool TelnetModule::begin(const char*, int, SnortConfig*)
{
    assert(!conf);
    conf = new TELNET_PROTO_CONF;
    return true;
}

bool TelnetModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const PegInfo* TelnetModule::get_pegs() const
{ return simple_pegs; }

PegCount* TelnetModule::get_counts() const
{ return (PegCount*)&tnstats; }

