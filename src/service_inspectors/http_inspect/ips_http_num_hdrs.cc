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
// ips_http_num_hdrs.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http_num_hdrs.h"

#include "framework/cursor.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "protocols/packet.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_flow_data.h"
#include "http_inspect.h"
#include "http_msg_head_shared.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

// Base class for all range-based rule options modules
HttpRangeRuleOptModule::HttpRangeRuleOptModule(const char* key_, const char* help,
    HTTP_RULE_OPT rule_opt_index_, const Parameter params[], ProfileStats& ps_) :
    HttpRuleOptModule(key_, help, rule_opt_index_, CAT_NONE, params), ps(ps_)
{
    const Parameter& range_param = params[0];
    // enforce that "~range" is the first Parameter
    assert(range_param.type ==  Parameter::PT_INTERVAL);
    num_range = range_param.get_range();
}

bool HttpRangeRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    range.init();
    return true;
}

bool HttpRangeRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~range"))
        return range.validate(v.get_string(), num_range);

    return HttpRuleOptModule::set(nullptr, v, nullptr);
}

// Base class for all range-based rule options
uint32_t HttpRangeIpsOption::hash() const
{
    uint32_t a = HttpIpsOption::hash();
    uint32_t b = range.hash();
    uint32_t c = 0;
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpRangeIpsOption::operator==(const IpsOption& ips) const
{
    const HttpRangeIpsOption& hio = static_cast<const HttpRangeIpsOption&>(ips);
    return HttpIpsOption::operator==(ips) &&
           range == hio.range;
}

IpsOption::EvalStatus HttpRangeIpsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(ps);

    const HttpInspect* const hi = eval_helper(p);
    if (hi == nullptr)
        return NO_MATCH;

    const int32_t count = get_num(hi, p);
    if (count != STAT_NOT_PRESENT && range.eval(count))
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// max_header_line
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_max_header_line"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on longest header line"

static const Parameter http_max_header_line_params[] =
{
    { "~range", Parameter::PT_INTERVAL, "0:65535", nullptr,
        "check that longest line of current header is in given range" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the version from the request message even when examining the response" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* max_header_line_mod_ctor()
{
    return new HttpNumRuleOptModule<HTTP_RANGE_MAX_HEADER_LINE, PS_HEADER>(IPS_OPT, IPS_HELP,
        http_max_header_line_params);
}

static const IpsApi max_header_line_api =
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
        max_header_line_mod_ctor,
        HttpRangeRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumIpsOption<&HttpInspect::http_get_max_header_line>::opt_ctor,
    HttpRangeIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// max_trailer_line
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_max_trailer_line"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on longest trailer line"

static const Parameter http_max_trailer_line_params[] =
{
    { "~range", Parameter::PT_INTERVAL, "0:65535", nullptr,
        "check that longest line of current trailer is in given range" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the version from the request message even when examining the response" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* max_trailer_line_mod_ctor()
{
    return new HttpNumRuleOptModule<HTTP_RANGE_MAX_TRAILER_LINE, PS_TRAILER>(IPS_OPT, IPS_HELP,
        http_max_trailer_line_params);
}

static const IpsApi max_trailer_line_api =
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
        max_trailer_line_mod_ctor,
        HttpRangeRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumIpsOption<&HttpInspect::http_get_max_header_line>::opt_ctor,
    HttpRangeIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// num_cookies
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_num_cookies"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on number of cookies"

static const Parameter http_num_cookies_params[] =
{
    { "~range", Parameter::PT_INTERVAL, "0:65535", nullptr,
        "check that number of cookies of current header are in given range" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the version from the request message even when examining the response" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* num_cookies_mod_ctor()
{
    return new HttpNumRuleOptModule<HTTP_RANGE_NUM_COOKIES, PS_HEADER>(IPS_OPT, IPS_HELP,
        http_num_cookies_params);
}

static const IpsApi num_cookies_api =
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
        num_cookies_mod_ctor,
        HttpRangeRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumIpsOption<&HttpInspect::http_get_num_cookies>::opt_ctor,
    HttpRangeIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// num_header_lines
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_num_headers"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on number of headers"

static const Parameter http_num_hdrs_params[] =
{
    { "~range", Parameter::PT_INTERVAL, "0:65535", nullptr,
        "check that number of headers of current buffer are in given range" },
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

static Module* num_hdrs_mod_ctor()
{
    return new HttpNumRuleOptModule<HTTP_RANGE_NUM_HDRS, PS_HEADER>(IPS_OPT, IPS_HELP,
        http_num_hdrs_params);
}

static const IpsApi num_headers_api =
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
        num_hdrs_mod_ctor,
        HttpRangeRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumIpsOption<&HttpInspect::http_get_num_headers>::opt_ctor,
    HttpRangeIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// num_trailer_lines
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_num_trailers"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on number of trailers"

static Module* num_trailers_mod_ctor()
{
    return new HttpNumRuleOptModule<HTTP_RANGE_NUM_TRAILERS, PS_TRAILER>(IPS_OPT, IPS_HELP,
        http_num_hdrs_params);
}

static const IpsApi num_trailers_api =
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
        num_trailers_mod_ctor,
        HttpRangeRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumIpsOption<&HttpInspect::http_get_num_headers>::opt_ctor,
    HttpRangeIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------
const BaseApi* ips_http_max_header_line = &max_header_line_api.base;
const BaseApi* ips_http_max_trailer_line = &max_trailer_line_api.base;
const BaseApi* ips_http_num_cookies = &num_cookies_api.base;
const BaseApi* ips_http_num_headers = &num_headers_api.base;
const BaseApi* ips_http_num_trailers = &num_trailers_api.base;
