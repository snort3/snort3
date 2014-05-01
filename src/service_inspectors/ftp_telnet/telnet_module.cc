/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// telnet_module.cc author Russ Combs <rucombs@cisco.com>

#include "telnet_module.h"
#include <sstream>
#include "main/snort_config.h"

using namespace std;

//-------------------------------------------------------------------------
// telnet module
//-------------------------------------------------------------------------

#define TELNET_AYT_OVERFLOW_STR                  \
        "(telnet) Consecutive Telnet AYT commands beyond threshold"
#define TELNET_ENCRYPTED_STR                     \
        "(telnet) Telnet traffic encrypted"
#define TELNET_SB_NO_SE_STR                      \
        "(telnet) Telnet Subnegotiation Begin Command without Subnegotiation End"

static const Parameter telnet_params[] =
{
    { "ayt_attack_thresh", Parameter::PT_INT, "-1:", "-1",
      "alert on this number of consecutive telnet AYT commands" },

    { "check_encrypted", Parameter::PT_BOOL, nullptr, "false",
      "check for end of encryption" },

    { "detect_anomalies", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted telnet and ftp" },

    { "normalize", Parameter::PT_BOOL, nullptr, "false",
      "eliminate escape sequences" },

    { "ports", Parameter::PT_BIT_LIST, "65535", "23",
      "specify known telnet ports" },

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
    Module("telnet", telnet_params, telnet_rules)
{
    conf = nullptr;
}

TelnetModule::~TelnetModule()
{
    if ( conf )
        delete conf;
}

bool TelnetModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ayt_attack_thresh") )
        conf->ayt_threshold = v.get_long();

    else if ( v.is("check_encrypted") )
        conf->detect_encrypted = v.get_bool();

    else if ( v.is("detect_anomalies") )
        conf->detect_anomalies = v.get_bool();

    else if ( v.is("encrypted_traffic") )
        conf->check_encrypted_data = v.get_bool();

    else if ( v.is("normalize") )
        conf->normalize = v.get_bool();

    else if ( v.is("ports") )
        v.get_bits(conf->ports);

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
    conf = new TELNET_PROTO_CONF;
    return true;
}

bool TelnetModule::end(const char*, int, SnortConfig*)
{
    return true;
}

