//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// reputation_module.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reputation_module.h"

#include <cassert>

#include "log/messages.h"
#include "utils/util.h"

#include "reputation_parse.h"

using namespace snort;
using namespace std;

#define REPUTATION_EVENT_BLACKLIST_STR \
    "packets blacklisted"
#define REPUTATION_EVENT_WHITELIST_STR \
    "packets whitelisted"
#define REPUTATION_EVENT_MONITOR_STR \
    "packets monitored"

static const Parameter s_params[] =
{
    { "blacklist", Parameter::PT_STRING, nullptr, nullptr,
      "blacklist file name with IP lists" },

    { "list_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory for IP lists and manifest file" },

    { "memcap", Parameter::PT_INT, "1:4095", "500",
      "maximum total MB of memory allocated" },

    { "nested_ip", Parameter::PT_ENUM, "inner|outer|all", "inner",
      "IP to use when there is IP encapsulation" },

    { "priority", Parameter::PT_ENUM, "blacklist|whitelist", "whitelist",
      "defines priority when there is a decision conflict during run-time" },

    { "scan_local", Parameter::PT_BOOL, nullptr, "false",
      "inspect local address defined in RFC 1918" },

    { "white", Parameter::PT_ENUM, "unblack|trust", "unblack",
      "specify the meaning of whitelist" },

    { "whitelist", Parameter::PT_STRING, nullptr, nullptr,
      "whitelist file name with IP lists" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap reputation_rules[] =
{
    { REPUTATION_EVENT_BLACKLIST, REPUTATION_EVENT_BLACKLIST_STR },
    { REPUTATION_EVENT_WHITELIST, REPUTATION_EVENT_WHITELIST_STR },
    { REPUTATION_EVENT_MONITOR, REPUTATION_EVENT_MONITOR_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// reputation module
//-------------------------------------------------------------------------

ReputationModule::ReputationModule() : Module(REPUTATION_NAME, REPUTATION_HELP, s_params)
{
    conf = nullptr;
}

ReputationModule::~ReputationModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* ReputationModule::get_rules() const
{ return reputation_rules; }

const PegInfo* ReputationModule::get_pegs() const
{ return reputation_peg_names; }

PegCount* ReputationModule::get_counts() const
{ return (PegCount*)&reputationstats; }

ProfileStats* ReputationModule::get_profile() const
{ return &reputation_perf_stats; }

bool ReputationModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("blacklist") )
        conf->blacklist_path = v.get_string();

    else if ( v.is("list_dir") )
        conf->list_dir = v.get_string();

    else if ( v.is("memcap") )
        conf->memcap = v.get_long();

    else if ( v.is("nested_ip") )
        conf->nested_ip = (NestedIP)v.get_long();

    else if ( v.is("priority") )
        conf->priority = (IPdecision)(v.get_long() + 1);

    else if ( v.is("scan_local") )
        conf->scanlocal = v.get_bool();

    else if ( v.is("white") )
        conf->white_action = (WhiteAction)v.get_long();

    else if ( v.is("whitelist") )
        conf->whitelist_path = v.get_string();

    else
        return false;

    return true;
}

ReputationConfig* ReputationModule::get_data()
{
    return conf;
}

bool ReputationModule::begin(const char*, int, SnortConfig*)
{
    conf = new ReputationConfig;
    return true;
}

bool ReputationModule::end(const char*, int, SnortConfig*)
{
    if ( (conf->priority == WHITELISTED_TRUST) && (conf->white_action == UNBLACK) )
    {
        ParseWarning(WARN_CONF, "Keyword \"whitelist\" for \"priority\" is "
            "not applied when white action is unblack.\n");
            conf->priority = WHITELISTED_UNBLACK;
    }

    return true;
}

