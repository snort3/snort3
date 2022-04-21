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
// ips_http_buffer.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from ips_http.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_http_buffer.h"

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

THREAD_LOCAL std::array<ProfileStats, BUFFER_PSI_MAX> HttpBufferRuleOptModule::http_buffer_ps;

bool HttpBufferRuleOptModule::begin(const char*, int, SnortConfig*)
{
    HttpRuleOptModule::begin(nullptr, 0, nullptr);
    scheme = false;
    host = false;
    port = false;
    path = false;
    query = false;
    fragment = false;

    switch (rule_opt_index)
    {
    case HTTP_BUFFER_RAW_STATUS:
    case HTTP_BUFFER_STAT_CODE:
    case HTTP_BUFFER_STAT_MSG:
        inspect_section = IS_HEADER;
        break;
    case HTTP_BUFFER_COOKIE:
    case HTTP_BUFFER_HEADER:
    case HTTP_BUFFER_METHOD:
    case HTTP_BUFFER_RAW_COOKIE:
    case HTTP_BUFFER_RAW_HEADER:
    case HTTP_BUFFER_RAW_REQUEST:
    case HTTP_BUFFER_RAW_URI:
    case HTTP_BUFFER_TRUE_IP:
    case HTTP_BUFFER_URI:
    case HTTP_BUFFER_VERSION:
        inspect_section = IS_FLEX_HEADER;
        break;
    case HTTP_BUFFER_CLIENT_BODY:
    case HTTP_BUFFER_RAW_BODY:
    case BUFFER_JS_DATA:
        inspect_section = IS_BODY;
        break;
    case HTTP_BUFFER_RAW_TRAILER:
    case HTTP_BUFFER_TRAILER:
        inspect_section = IS_TRAILER;
        is_trailer_opt = true;
        break;
    default:
        assert(false);
    }
    return true;
}


bool HttpBufferRuleOptModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("scheme"))
    {
        scheme = true;
        sub_id = UC_SCHEME;
    }
    else if (v.is("host"))
    {
        host = true;
        sub_id = UC_HOST;
    }
    else if (v.is("port"))
    {
        port = true;
        sub_id = UC_PORT;
    }
    else if (v.is("path"))
    {
        path = true;
        sub_id = UC_PATH;
    }
    else if (v.is("query"))
    {
        query = true;
        sub_id = UC_QUERY;
    }
    else if (v.is("fragment"))
    {
        fragment = true;
        sub_id = UC_FRAGMENT;
    }
    else
        HttpRuleOptModule::set(nullptr, v, nullptr);

    return true;
}


bool HttpBufferRuleOptModule::end(const char*, int, SnortConfig*)
{
    // Check for option conflicts
    if (scheme + host + port + path + query + fragment > 1)
        ParseError("Only specify one part of the URI");
    return HttpRuleOptModule::end(nullptr, 0, nullptr);
}

static InspectionBuffer::Type buf_map[] =
{
#if 0
    BUFFER_PSI_CLIENT_BODY, BUFFER_PSI_COOKIE, BUFFER_PSI_HEADER, BUFFER_PSI_METHOD,
    BUFFER_PSI_RAW_BODY, BUFFER_PSI_RAW_COOKIE, BUFFER_PSI_RAW_HEADER, BUFFER_PSI_RAW_REQUEST,
    BUFFER_PSI_RAW_STATUS, BUFFER_PSI_RAW_TRAILER, BUFFER_PSI_RAW_URI, BUFFER_PSI_STAT_CODE,
    BUFFER_PSI_STAT_MSG, BUFFER_PSI_TRAILER, BUFFER_PSI_TRUE_IP, BUFFER_PSI_URI, BUFFER_PSI_VERSION,
    BUFFER_PSI_JS_DATA, BUFFER_PSI_VBA_DATA, BUFFER_PSI_MAX
#endif
    InspectionBuffer::IBT_BODY,
    InspectionBuffer::IBT_COOKIE,
    InspectionBuffer::IBT_HEADER,
    InspectionBuffer::IBT_METHOD,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_RAW_HEADER,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_RAW_HEADER,
    InspectionBuffer::IBT_RAW_KEY,
    InspectionBuffer::IBT_STAT_CODE,
    InspectionBuffer::IBT_STAT_MSG,
    InspectionBuffer::IBT_HEADER,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_KEY,
    InspectionBuffer::IBT_MAX,
    InspectionBuffer::IBT_JS_DATA,
    InspectionBuffer::IBT_VBA,
    InspectionBuffer::IBT_MAX
};

IpsOption::EvalStatus HttpBufferIpsOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(HttpBufferRuleOptModule::http_buffer_ps[idx]);

    HttpInspect* hi = const_cast<HttpInspect*>(eval_helper(p));
    if (hi == nullptr)
        return NO_MATCH;

    if (p->packet_flags & PKT_FAST_PAT_EVAL)
    {
        InspectionBuffer buf;
        InspectionBuffer::Type ibt = buf_map[idx];

        if (ibt == InspectionBuffer::IBT_MAX)
            return NO_MATCH;

        if (!hi->get_fp_buf(ibt, p, buf))
            return NO_MATCH;

        c.set(key, buf.data, buf.len);
        return MATCH;
    }

    const Field& http_buffer = hi->http_get_buf(p, buffer_info);
    if (http_buffer.length() <= 0)
        return NO_MATCH;

    c.set(key, http_buffer.start(), http_buffer.length());

    return MATCH;
}


//-------------------------------------------------------------------------
// http_client_body
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_client_body"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the request body"

static Module* client_body_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_CLIENT_BODY, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_CLIENT_BODY);
}

static const IpsApi client_body_api =
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
        client_body_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_cookie
//-------------------------------------------------------------------------

static const Parameter http_cookie_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the cookie from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_cookie"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP cookie"

static Module* cookie_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_COOKIE, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_COOKIE, http_cookie_params);
}

static const IpsApi cookie_api =
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
        cookie_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_header
//-------------------------------------------------------------------------

// FIXIT-M add match_unknown option to look at HEAD__UNKNOWN.

// FIXIT-M if http_header is the fast pattern buffer and the content to be
// matched appears in the normalized field but not in the raw field
// detection will fail.

static const Parameter http_header_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr,
        "restrict to given header. Header name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the headers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_header"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the normalized headers"

static Module* header_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_HEADER, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_HEADER, http_header_params);
}

static const IpsApi header_api =
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
        header_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_method
//-------------------------------------------------------------------------

static const Parameter http_method_params[] =
{
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_method"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP request method"

static Module* method_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_METHOD, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_METHOD, http_method_params);
}

static const IpsApi method_api =
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
        method_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_body
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_raw_body"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized message body"

static Module* raw_body_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_BODY, CAT_SET_OTHER,
        BUFFER_PSI_RAW_BODY);
}

static const IpsApi raw_body_api =
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
        raw_body_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_cookie
//-------------------------------------------------------------------------

static const Parameter http_raw_cookie_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the cookie from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_cookie"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized cookie"

static Module* raw_cookie_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_COOKIE, CAT_SET_OTHER,
        BUFFER_PSI_RAW_COOKIE, http_raw_cookie_params);
}

static const IpsApi raw_cookie_api =
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
        raw_cookie_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_header
//-------------------------------------------------------------------------

static const Parameter http_raw_header_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr,
        "restrict to given header. Header name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the headers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_header"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized headers"

static Module* raw_header_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_HEADER, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_RAW_HEADER, http_raw_header_params);
}

static const IpsApi raw_header_api =
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
        raw_header_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_request
//-------------------------------------------------------------------------

static const Parameter http_raw_request_params[] =
{
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_request"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized request line"

static Module* raw_request_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_REQUEST, CAT_SET_OTHER,
        BUFFER_PSI_RAW_REQUEST, http_raw_request_params);
}

static const IpsApi raw_request_api =
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
        raw_request_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_status
//-------------------------------------------------------------------------

static const Parameter http_raw_status_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_status"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized status line"

static Module* raw_status_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_STATUS, CAT_SET_OTHER,
        BUFFER_PSI_RAW_STATUS, http_raw_status_params);
}

static const IpsApi raw_status_api =
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
        raw_status_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_trailer
//-------------------------------------------------------------------------

static const Parameter http_raw_trailer_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr,
        "restrict to given trailer. Trailer name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the trailers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP response message headers (must be combined with request)"
        },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP response message body (must be combined with request)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_trailer"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized trailers"

static Module* raw_trailer_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_TRAILER, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_RAW_TRAILER, http_raw_trailer_params);
}

static const IpsApi raw_trailer_api =
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
        raw_trailer_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_uri
//-------------------------------------------------------------------------

static const Parameter http_raw_uri_params[] =
{
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { "scheme", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against scheme section of URI only" },
    { "host", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against host section of URI only" },
    { "port", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against port section of URI only" },
    { "path", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against path section of URI only" },
    { "query", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against query section of URI only" },
    { "fragment", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against fragment section of URI only" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_uri"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized URI"

static Module* raw_uri_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_RAW_URI, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_RAW_URI, http_raw_uri_params);
}

static const IpsApi raw_uri_api =
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
        raw_uri_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_code
//-------------------------------------------------------------------------

static const Parameter http_stat_code_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_stat_code"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP status code"

static Module* stat_code_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_STAT_CODE, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_STAT_CODE, http_stat_code_params);
}

static const IpsApi stat_code_api =
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
        stat_code_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_msg
//-------------------------------------------------------------------------

static const Parameter http_stat_msg_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_stat_msg"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP status message"

static Module* stat_msg_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_STAT_MSG, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_STAT_MSG, http_stat_msg_params);
}

static const IpsApi stat_msg_api =
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
        stat_msg_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_trailer
//-------------------------------------------------------------------------

static const Parameter http_trailer_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr, "restrict to given trailer" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against the trailers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP response message headers (must be combined with request)"
        },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body (must be combined with request)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_trailer"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the normalized trailers"

static Module* trailer_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_TRAILER, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_TRAILER, http_trailer_params);
}

static const IpsApi trailer_api =
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
        trailer_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_true_ip
//-------------------------------------------------------------------------

static const Parameter http_true_ip_params[] =
{
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_true_ip"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the final client IP address"

static Module* true_ip_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_TRUE_IP, CAT_SET_OTHER,
        BUFFER_PSI_TRUE_IP, http_true_ip_params);
}

static const IpsApi true_ip_api =
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
        true_ip_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_uri
//-------------------------------------------------------------------------

static const Parameter http_uri_params[] =
{
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "this rule is limited to examining HTTP message headers" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "parts of this rule examine HTTP message trailers" },
    { "scheme", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against scheme section of URI only" },
    { "host", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against host section of URI only" },
    { "port", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against port section of URI only" },
    { "path", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against path section of URI only" },
    { "query", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against query section of URI only" },
    { "fragment", Parameter::PT_IMPLIED, nullptr, nullptr,
        "match against fragment section of URI only" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_uri"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the normalized URI buffer"

static Module* uri_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_URI, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_URI, http_uri_params);
}

static const IpsApi uri_api =
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
        uri_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_version
//-------------------------------------------------------------------------

static const Parameter http_version_params[] =
{
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

#undef IPS_OPT
#define IPS_OPT "http_version"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the version buffer"

static Module* version_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, HTTP_BUFFER_VERSION, CAT_SET_OTHER,
        BUFFER_PSI_VERSION, http_version_params);
}

static const IpsApi version_api =
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
        version_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// js_data
//-------------------------------------------------------------------------
//

#undef IPS_OPT
#define IPS_OPT "js_data"
#undef IPS_HELP
#define IPS_HELP "rule option to set detection cursor to normalized JavaScript data"
static Module* js_data_mod_ctor()
{
    return new HttpBufferRuleOptModule(IPS_OPT, IPS_HELP, BUFFER_JS_DATA, CAT_SET_FAST_PATTERN,
        BUFFER_PSI_JS_DATA);
}

static const IpsApi js_data_api =
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
        js_data_mod_ctor,
        HttpBufferRuleOptModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    HttpBufferIpsOption::opt_ctor,
    HttpBufferIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

const BaseApi* ips_http_client_body = &client_body_api.base;
const BaseApi* ips_http_cookie = &cookie_api.base;
const BaseApi* ips_http_header = &header_api.base;
const BaseApi* ips_http_method = &method_api.base;
const BaseApi* ips_http_raw_body = &raw_body_api.base;
const BaseApi* ips_http_raw_cookie = &raw_cookie_api.base;
const BaseApi* ips_http_raw_header = &raw_header_api.base;
const BaseApi* ips_http_raw_request = &raw_request_api.base;
const BaseApi* ips_http_raw_status = &raw_status_api.base;
const BaseApi* ips_http_raw_trailer = &raw_trailer_api.base;
const BaseApi* ips_http_raw_uri = &raw_uri_api.base;
const BaseApi* ips_http_stat_code = &stat_code_api.base;
const BaseApi* ips_http_stat_msg = &stat_msg_api.base;
const BaseApi* ips_http_trailer = &trailer_api.base;
const BaseApi* ips_http_true_ip = &true_ip_api.base;
const BaseApi* ips_http_uri = &uri_api.base;
const BaseApi* ips_http_version = &version_api.base;
const BaseApi* ips_js_data = &js_data_api.base;
