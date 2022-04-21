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
// ips_http_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http_test.h"

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

THREAD_LOCAL std::array<ProfileStats, TEST_PSI_MAX> HttpTestRuleOptModule::http_test_ps;

const std::string hdr_test_range = "0:999999999999999999"; // max 18 digit uint

bool HttpTestRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    check.init();
    numeric = NV_UNDEFINED;
    absent = false;
    if (rule_opt_index == HTTP_HEADER_TEST)
        inspect_section = IS_FLEX_HEADER;
    else
    {
        inspect_section = IS_TRAILER;
        is_trailer_opt = true;
    }

    return true;
}

bool HttpTestRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("check"))
    {
        return check.validate(v.get_string(), hdr_test_range.c_str());
    }
    else if (v.is("numeric"))
    {
        numeric = v.get_bool()? NV_TRUE : NV_FALSE;
    }
    else if (v.is("absent"))
    {
        absent = true;
    }
    else
    {
        return HttpRuleOptModule::set(nullptr, v, nullptr);
    }

    return true;
}

bool HttpTestRuleOptModule::end(const char*, int, SnortConfig*)
{
    if (sub_id == 0)
        ParseError("Specify field name");

    if (!absent && !check.is_set() && numeric == NV_UNDEFINED)
        ParseError("check, numeric, or absent should be specified");

    if ((absent && (check.is_set() || numeric != NV_UNDEFINED)) ||
        (check.is_set() && numeric == NV_FALSE))
        ParseWarning(WARN_RULES, "conflicting suboptions");

    return HttpRuleOptModule::end(nullptr, 0, nullptr);
}

uint32_t HttpTestIpsOption::hash() const
{
    uint32_t a = HttpIpsOption::hash();
    uint32_t b = check.hash();
    uint32_t c = numeric;
    mix(a,b,c);
    c = absent ? 1 : 0;
    mix(a,b,c);
    finalize(a,b,c);
    return c;
}

bool HttpTestIpsOption::operator==(const IpsOption& ips) const
{
    const HttpTestIpsOption& hio = static_cast<const HttpTestIpsOption&>(ips);
    return HttpIpsOption::operator==(ips) &&
           check == hio.check &&
           numeric == hio.numeric &&
           absent == hio.absent;
}

static int64_t get_decimal_num(enum NumericValue& is_numeric, const uint8_t* start, int32_t length)
{
    int64_t total = 0;
    int32_t k = 0;
    do
    {
        int value = start[k] - '0';
        if ((value < 0) || (value > 9))
        {
            is_numeric = NV_FALSE;
            return -1;
        }
        total = total*10 + value;
    }
    while (++k < length);

    is_numeric = NV_TRUE;
    return total;
}

IpsOption::EvalStatus HttpTestIpsOption::eval_header_test(const Field& http_buffer) const
{
    bool is_absent = false;
    enum NumericValue is_numeric = NV_UNDEFINED;
    int64_t num = 0;

    const int32_t length = http_buffer.length();
    if (length <= 0)
        is_absent = true;
    // Limit to 18 decimal digits, to fit comfortably into int64_t.
    else if (length <= 18)
        num = get_decimal_num(is_numeric, http_buffer.start(), length);
    else
        is_numeric = NV_FALSE;

    const bool absent_passed = !absent || (absent && is_absent);
    const bool numeric_passed = (numeric == NumericValue::NV_UNDEFINED) ||
                                (is_numeric == numeric);
    const bool range_passed = !check.is_set() || (is_numeric == NV_TRUE && check.eval(num));

    return (absent_passed && numeric_passed && range_passed) ? MATCH : NO_MATCH;
}


IpsOption::EvalStatus HttpTestIpsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(HttpTestRuleOptModule::http_test_ps[idx]);

    const HttpInspect* const hi = eval_helper(p);
    if (hi == nullptr)
        return NO_MATCH;
    
    const Field& http_buffer = hi->http_get_buf(p, buffer_info);

    return eval_header_test(http_buffer);
}


//-------------------------------------------------------------------------
// http_header_test
//-------------------------------------------------------------------------
#undef IPS_OPT
#define IPS_OPT "http_header_test"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on specified header field, \
check whether it is a number, or check if the field is absent"

static const Parameter hdr_test_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr,
        "Header to perform check on. Header name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the headers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { "check", Parameter::PT_INTERVAL, hdr_test_range.c_str(), nullptr,
        "range check to perform on header value" },
    { "numeric", Parameter::PT_BOOL, nullptr, nullptr,
        "header value is a number" },
    { "absent", Parameter::PT_IMPLIED, nullptr, nullptr,
        "header is absent" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* http_header_test_mod_ctor()
{
    return new HttpTestRuleOptModule(IPS_OPT, IPS_HELP, HTTP_HEADER_TEST, CAT_NONE,
        TEST_PSI_HEADER_TEST, hdr_test_params);
}

static const IpsApi header_test_api =
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
        http_header_test_mod_ctor,
        HttpTestRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpTestIpsOption::opt_ctor,
    HttpTestIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_trailer_test
//-------------------------------------------------------------------------
static const Parameter trailer_test_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr,
        "Trailer to perform check on. Trailer name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the trailers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "check", Parameter::PT_INTERVAL, hdr_test_range.c_str(), nullptr,
        "range check to perform on trailer value" },
    { "numeric", Parameter::PT_BOOL, nullptr, nullptr,
        "trailer value is a number" },
    { "absent", Parameter::PT_IMPLIED, nullptr, nullptr,
        "trailer is absent" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_trailer_test"
#undef IPS_HELP
#define IPS_HELP "rule option to perform range check on specified trailer field, \
check whether it is a number, or check if the field is absent"

static Module* http_trailer_test_mod_ctor()
{
    return new HttpTestRuleOptModule(IPS_OPT, IPS_HELP, HTTP_TRAILER_TEST, CAT_NONE,
        TEST_PSI_TRAILER_TEST, trailer_test_params);
}

static const IpsApi trailer_test_api =
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
        http_trailer_test_mod_ctor,
        HttpTestRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpTestIpsOption::opt_ctor,
    HttpTestIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

const BaseApi* ips_http_header_test = &header_test_api.base;
const BaseApi* ips_http_trailer_test = &trailer_test_api.base;
