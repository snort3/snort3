//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

THREAD_LOCAL std::array<ProfileStats, NUM_HDRS_PSI_MAX> HttpNumHdrsRuleOptModule::http_num_hdrs_ps;

const std::string hdrs_num_range = "0:" + std::to_string(HttpMsgHeadShared::MAX_HEADERS);

bool HttpNumHdrsRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    range.init();
    if (rule_opt_index == HTTP_RANGE_NUM_HDRS)
        inspect_section = IS_FLEX_HEADER;
    else
    {
        inspect_section = IS_TRAILER;
        is_trailer_opt = true;
    }

    return true;
}

bool HttpNumHdrsRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~range"))
        return range.validate(v.get_string(), hdrs_num_range.c_str());
    
    return HttpRuleOptModule::set(nullptr, v, nullptr);
}


uint32_t HttpNumHdrsIpsOption::hash() const
{
    uint32_t a = HttpIpsOption::hash();
    uint32_t b = range.hash();
    uint32_t c = 0;
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpNumHdrsIpsOption::operator==(const IpsOption& ips) const
{
    const HttpNumHdrsIpsOption& hio = static_cast<const HttpNumHdrsIpsOption&>(ips);
    return HttpIpsOption::operator==(ips) &&
           range == hio.range;
}

IpsOption::EvalStatus HttpNumHdrsIpsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(HttpNumHdrsRuleOptModule::http_num_hdrs_ps[idx]);

    const HttpInspect* const hi = eval_helper(p);
    if (hi == nullptr)
        return NO_MATCH;

    const int32_t num_lines = hi->http_get_num_headers(p, buffer_info);
    if (num_lines != HttpCommon::STAT_NOT_PRESENT && range.eval(num_lines))
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// num_header_lines
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_num_headers"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on number of headers"

static const Parameter http_num_hdrs_params[] =
{
    { "~range", Parameter::PT_INTERVAL, hdrs_num_range.c_str(), nullptr,
        "check that number of headers of current buffer are in given range" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the version from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* num_hdrs_mod_ctor()
{
    return new HttpNumHdrsRuleOptModule(IPS_OPT, IPS_HELP, HTTP_RANGE_NUM_HDRS, CAT_NONE,
	NUM_HDRS_PSI_HDRS, http_num_hdrs_params);
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
        HttpNumHdrsRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumHdrsIpsOption::opt_ctor,
    HttpNumHdrsIpsOption::opt_dtor,
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
    return new HttpNumHdrsRuleOptModule(IPS_OPT, IPS_HELP, HTTP_RANGE_NUM_TRAILERS, CAT_NONE,
        NUM_HDRS_PSI_TRAILERS, http_num_hdrs_params);
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
        HttpNumHdrsRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpNumHdrsIpsOption::opt_ctor,
    HttpNumHdrsIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------
const BaseApi* ips_http_num_headers = &num_headers_api.base;
const BaseApi* ips_http_num_trailers = &num_trailers_api.base;

