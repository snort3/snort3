//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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
#include <cerrno>
#include <cstdlib>

#include "log/messages.h"

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
    { "embedded_cip_path", Parameter::PT_STRING, nullptr, nullptr,
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
        embedded_path = v.get_string();
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
    conf = new CipProtoConf();

    embedded_path.clear();

    return true;
}

// parse one whitespace-separated token of embedded_cip_path as an integer;
// the entire token must be consumed and the value must fit in max
static bool parse_id(Value& v, const char* name, unsigned long max, unsigned long& id)
{
    std::string tok;

    if ( !v.get_next_token(tok) )
    {
        ParseError("cip: embedded_cip_path requires '<class id> <service id>'");
        return false;
    }

    char* end = nullptr;
    errno = 0;
    id = ::strtoul(tok.c_str(), &end, 0);

    if ( end == tok.c_str() or *end or errno == ERANGE or id > max )
    {
        ParseError("cip: embedded_cip_path %s '%s' is not in 0:%lu", name, tok.c_str(), max);
        return false;
    }

    return true;
}

bool CipModule::end(const char*, int, SnortConfig*)
{
    conf->embedded_cip_enabled = false;
    conf->embedded_cip_class_id = 0;
    conf->embedded_cip_service_id = 0;

    // not configured, or explicitly disabled with the historical "false" spelling
    if ( embedded_path.empty() or embedded_path == "false" )
        return true;

    Value v(embedded_path.c_str());
    v.set_first_token();

    unsigned long class_id = 0;
    unsigned long service_id = 0;

    if ( !parse_id(v, "class id", UINT32_MAX, class_id) or
         !parse_id(v, "service id", UINT8_MAX, service_id) )
        return false;

    conf->embedded_cip_class_id = static_cast<uint32_t>(class_id);
    conf->embedded_cip_service_id = static_cast<uint8_t>(service_id);
    conf->embedded_cip_enabled = true;

    return true;
}

