//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
// ips_http_version.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http_version.h"

#include "framework/cursor.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "protocols/packet.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_inspect.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

THREAD_LOCAL ProfileStats HttpVersionRuleOptModule::http_version_ps;

bool HttpVersionRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    pdu_section = PS_HEADER;
    version_flags = 0;
    return true;
}

static const std::map <std::string, VersionId> VersionStrToEnum =
{
    { "malformed", VERS__PROBLEMATIC },
    { "other", VERS__OTHER },
    { "1.0", VERS_1_0 },
    { "1.1", VERS_1_1 },
    { "2.0", VERS_2_0 },
    { "3.0", VERS_3_0 },
    { "0.9", VERS_0_9 }
};

bool HttpVersionRuleOptModule::parse_version_list(Value& v)
{
    v.set_first_token();
    std::string tok;

    while ( v.get_next_token(tok) )
    {
        if (tok[0] == '"')
            tok.erase(0, 1);

        if (tok.length() == 0)
            continue;

        if (tok[tok.length()-1] == '"')
            tok.erase(tok.length()-1, 1);

        auto iter = VersionStrToEnum.find(tok);
        if (iter == VersionStrToEnum.end())
        {
            ParseError("Unrecognized version %s\n", tok.c_str());
            return false;
        }

        version_flags[iter->second - VERS__MIN] = true;
    }
    return true;
}

bool HttpVersionRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~version_list"))
    {
        return parse_version_list(v);
    }
    return HttpRuleOptModule::set(nullptr, v, nullptr);
}

uint32_t HttpVersionIpsOption::hash() const
{
    uint32_t a = HttpIpsOption::hash();
    uint32_t b = (uint32_t)version_flags.to_ulong();
    uint32_t c = 0;
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpVersionIpsOption::operator==(const IpsOption& ips) const
{
    const HttpVersionIpsOption& hio = static_cast<const HttpVersionIpsOption&>(ips);
    return HttpIpsOption::operator==(ips) &&
           version_flags == hio.version_flags;
}

IpsOption::EvalStatus HttpVersionIpsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(HttpVersionRuleOptModule::http_version_ps);

    const HttpInspect* const hi = eval_helper(p);
    if (hi == nullptr)
        return NO_MATCH;

    const VersionId version = hi->http_get_version_id(p, buffer_info);

    if (version_flags[version - HttpEnums::VERS__MIN])
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// http_version_match
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_version_match"
#undef IPS_HELP
#define IPS_HELP "rule option to match version to listed values"

static const Parameter version_match_params[] =
{
    { "~version_list", Parameter::PT_STRING, nullptr, nullptr,
        "space-separated list of versions to match" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the version from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "option is no longer used and will be removed in a future release" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "option is no longer used and will be removed in a future release" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "option is no longer used and will be removed in a future release" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* version_match_mod_ctor()
{
    return new HttpVersionRuleOptModule(IPS_OPT, IPS_HELP, HTTP_VERSION_MATCH, CAT_NONE,
        version_match_params);
}

static const IpsApi version_match_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        1,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        IPS_HELP,
        version_match_mod_ctor,
        HttpVersionRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpVersionIpsOption::opt_ctor,
    HttpVersionIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------
const BaseApi* ips_http_version_match = &version_match_api.base;
