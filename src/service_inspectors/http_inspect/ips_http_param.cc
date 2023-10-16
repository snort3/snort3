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
// ips_http_param.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http_param.h"

#include "framework/cursor.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "protocols/packet.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_inspect.h"
#include "http_msg_section.h"
#include "http_param.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

THREAD_LOCAL ProfileStats HttpParamRuleOptModule::http_param_ps;

bool HttpParamRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    param.clear();
    nocase = false;
    pdu_section = PS_HEADER;
    return true;
}

bool HttpParamRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~param"))
    {
        std::string bc = v.get_string();
        bool negated = false;
        if (!parse_byte_code(bc.c_str(), negated, param) or negated)
            ParseError("Invalid http_param");
    }
    else if (v.is("nocase"))
    {
        nocase = true;
    }
    return true;
}

uint32_t HttpParamIpsOption::hash() const
{
    uint32_t a = HttpIpsOption::hash();
    uint32_t b = http_param.is_nocase() ? 1 : 0;
    uint32_t c = 0;
    mix_str(a,b,c,http_param.c_str(),http_param.length());
    finalize(a,b,c);
    return a;
}

bool HttpParamRuleOptModule::end(const char*, int, SnortConfig*)
{
    if (param.length() == 0)
        ParseError("Specify parameter name");
    return true;
}

bool HttpParamIpsOption::operator==(const IpsOption& ips) const
{
    const HttpParamIpsOption& hio = static_cast<const HttpParamIpsOption&>(ips);

    return HttpIpsOption::operator==(ips) &&
           http_param == hio.http_param;
}

bool HttpParamIpsOption::retry(Cursor& current_cursor, const Cursor&)
{
    HttpCursorData* cd = (HttpCursorData*)current_cursor.get_data(HttpCursorData::id);

    if (cd)
        return cd->retry();

    return false;
}

IpsOption::EvalStatus HttpParamIpsOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(HttpParamRuleOptModule::http_param_ps);

    const HttpInspect* const hi = eval_helper(p);
    if (hi == nullptr)
        return NO_MATCH;

    const Field& http_buffer = hi->http_get_param_buf(c, p, http_param);
    if (http_buffer.length() <= 0)
        return NO_MATCH;

    c.set(key, http_buffer.start(), http_buffer.length());

    return MATCH;
}

section_flags HttpParamIpsOption::get_pdu_section(bool) const
{
    // Works on URI or client body
    return section_to_flag(snort::PS_HEADER_BODY);
}


//-------------------------------------------------------------------------
// http_param
//-------------------------------------------------------------------------

static const Parameter http_param_params[] =
{
    { "~param", Parameter::PT_STRING, nullptr, nullptr,
        "parameter to match" },
    { "nocase", Parameter::PT_IMPLIED, nullptr, nullptr,
        "case insensitive match" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_param"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the value of the specified HTTP parameter key which may be in the query or body"

static Module* param_mod_ctor()
{
    return new HttpParamRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_PARAM, CAT_SET_OTHER,
        http_param_params);
}

static const IpsApi param_api =
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
        param_mod_ctor,
        HttpParamRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpParamIpsOption::opt_ctor,
    HttpParamIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

const BaseApi* ips_http_param = &param_api.base;
