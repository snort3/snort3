//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

// cip_module.cc author Jian Wu <jiawu2@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip_module.h"

#include <cassert>

#include "cip.h"

using namespace snort;
using namespace std;

#define CIP_MALFORMED_STR "CIP data is malformed"
#define CIP_NON_CONFORMING_STR "CIP data is non-conforming to ODVA standard"
#define CIP_CONNECTION_LIMIT_STR \
    "CIP connection limit exceeded. Least recently used connection removed"
#define CIP_REQUEST_LIMIT_STR "CIP unconnected request limit exceeded. Oldest request removed"

static const Parameter c_params[] =
{
    { "embedded_cip_path", Parameter::PT_STRING, nullptr, "false",
      "check embedded CIP path" },
    { "unconnected_timeout", Parameter::PT_INT, "0:360", "300",
      "unconnected timeout in seconds" },
    { "max_cip_connections", Parameter::PT_INT, "1:10000", "100",
      "max cip connections" },
    { "max_unconnected_messages", Parameter::PT_INT, "1:10000", "100",
      "max unconnected cip messages" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap cip_rules[] =
{
    { CIP_MALFORMED, CIP_MALFORMED_STR },
    { CIP_NON_CONFORMING, CIP_NON_CONFORMING_STR },
    { CIP_CONNECTION_LIMIT, CIP_CONNECTION_LIMIT_STR },
    { CIP_REQUEST_LIMIT, CIP_REQUEST_LIMIT_STR },
    { 0, nullptr }
};

THREAD_LOCAL CipStats cip_stats;

static const PegInfo cip_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::SUM, "session", "total sessions" },
    { CountType::NOW, "concurrent_sessions", "total concurrent SIP sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent SIP sessions" },
    { CountType::END, nullptr, nullptr },
};

//-------------------------------------------------------------------------
// cip module
//-------------------------------------------------------------------------

CipModule::CipModule() : Module(CIP_NAME, CIP_HELP, c_params)
{
    conf = nullptr;
}

CipModule::~CipModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* CipModule::get_rules() const
{ return cip_rules; }

const PegInfo* CipModule::get_pegs() const
{ return cip_pegs; }

PegCount* CipModule::get_counts() const
{ return (PegCount*)&cip_stats; }

ProfileStats* CipModule::get_profile() const
{ return &cip_perf_stats; }

bool CipModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("embedded_cip_path") )
    {
        conf->embedded_cip_enabled = true;
        embedded_path = v.get_string();
    }
    else if ( v.is("unconnected_timeout") )
        conf->unconnected_timeout = v.get_uint32();

    else if ( v.is("max_cip_connections") )
        conf->max_cip_connections = v.get_uint32();

    else if ( v.is("max_unconnected_messages") )
        conf->max_unconnected_messages = v.get_uint32();

    return true;
}

CipProtoConf* CipModule::get_data()
{
    CipProtoConf* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool CipModule::begin(const char*, int, SnortConfig*)
{
    assert(!conf);
    conf = new CipProtoConf;

    conf->embedded_cip_enabled = false;

    return true;
}

bool CipModule::end(const char*, int, SnortConfig*)
{
    Value v(embedded_path.c_str());
    std::string tok;
    v.set_first_token();

    if ( v.get_next_token(tok) )
    {
        conf->embedded_cip_class_id = static_cast<uint32_t>(::strtol(tok.c_str(), nullptr, 0));
    }

    if (v.get_next_token(tok) )
    {
        conf->embedded_cip_service_id = static_cast<uint8_t>(::strtol(tok.c_str(), nullptr, 0));
    }

    return true;
}

