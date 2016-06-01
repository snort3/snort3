//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ips_nhttp.cc author Tom Peters <thopeter@cisco.com>

#include <array>

#include "protocols/packet.h"
#include "flow/flow.h"
#include "detection/detection_defines.h"
#include "framework/cursor.h"
#include "hash/sfhashfcn.h"
#include "log/messages.h"

#include "nhttp_inspect.h"
#include "nhttp_msg_head_shared.h"
#include "ips_nhttp.h"

using namespace NHttpEnums;

THREAD_LOCAL std::array<ProfileStats, PSI_MAX> NHttpCursorModule::http_ps;

bool NHttpCursorModule::begin(const char*, int, SnortConfig*)
{
    para_list.reset();
    sub_id = 0;
    form = 0;
    switch (buffer_index)
    {
    case NHTTP_BUFFER_URI:
    case NHTTP_BUFFER_RAW_URI:
    case NHTTP_BUFFER_STAT_CODE:
    case NHTTP_BUFFER_STAT_MSG:
    case NHTTP_BUFFER_VERSION:
    case NHTTP_BUFFER_METHOD:
    case NHTTP_BUFFER_HEADER:
    case NHTTP_BUFFER_RAW_HEADER:
    case NHTTP_BUFFER_COOKIE:
    case NHTTP_BUFFER_RAW_COOKIE:
    case NHTTP_BUFFER_RAW_REQUEST:
    case NHTTP_BUFFER_RAW_STATUS:
        inspect_section = IS_DETECTION;
        break;
    case NHTTP_BUFFER_CLIENT_BODY:
        inspect_section = IS_BODY;
        break;
    case NHTTP_BUFFER_TRAILER:
    case NHTTP_BUFFER_RAW_TRAILER:
        inspect_section = IS_TRAILER;
        break;
    default:
        assert(false);
    }
    return true;
}

bool NHttpCursorModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("field"))
    {
        if (sub_id != 0)
            ParseError("Only specify one header field to match");
        para_list.field = v.get_string();
        const int32_t name_size = (para_list.field.size() <= MAX_FIELD_NAME_LENGTH) ?
            para_list.field.size() : MAX_FIELD_NAME_LENGTH;
        uint8_t lower_name[MAX_FIELD_NAME_LENGTH];
        for (int32_t k=0; k < name_size; k++)
        {
            lower_name[k] = ((para_list.field[k] < 'A') || (para_list.field[k] > 'Z')) ?
                para_list.field[k] : para_list.field[k] - ('A' - 'a');
        }
        sub_id = str_to_code(lower_name, name_size, NHttpMsgHeadShared::header_list);
        if (sub_id == STAT_OTHER)
            ParseError("Unrecognized header field name");
    }
    else if (v.is("request"))
    {
        para_list.request = true;
        form |= FORM_REQUEST;
    }
    else if (v.is("with_header"))
    {
        para_list.with_header = true;
        inspect_section = IS_DETECTION;
    }
    else if (v.is("with_body"))
    {
        para_list.with_body = true;
        inspect_section = IS_BODY;
    }
    else if (v.is("with_trailer"))
    {
        para_list.with_trailer = true;
        inspect_section = IS_TRAILER;
    }
    else if (v.is("scheme"))
    {
        para_list.scheme = true;
        sub_id = UC_SCHEME;
    }
    else if (v.is("host"))
    {
        para_list.host = true;
        sub_id = UC_HOST;
    }
    else if (v.is("port"))
    {
        para_list.port = true;
        sub_id = UC_PORT;
    }
    else if (v.is("path"))
    {
        para_list.path = true;
        sub_id = UC_PATH;
    }
    else if (v.is("query"))
    {
        para_list.query = true;
        sub_id = UC_QUERY;
    }
    else if (v.is("fragment"))
    {
        para_list.fragment = true;
        sub_id = UC_FRAGMENT;
    }
    else
    {
        return false;
    }
    return true;
}

bool NHttpCursorModule::end(const char*, int, SnortConfig*)
{
    // Check for option conflicts
    if (para_list.with_header + para_list.with_body + para_list.with_trailer > 1)
        ParseError("Only specify one with_ option. Use the one that happens last.");
    if (((buffer_index == NHTTP_BUFFER_TRAILER) || (buffer_index == NHTTP_BUFFER_RAW_TRAILER)) &&
        (para_list.with_header || para_list.with_body) &&
        !para_list.request)
        ParseError("Trailers with with_ option must also specify request");
    if (para_list.scheme + para_list.host + para_list.port + para_list.path + para_list.query +
          para_list.fragment > 1)
        ParseError("Only specify one part of the URI");
    return true;
}

void NHttpCursorModule::NHttpRuleParaList::reset()
{
    field.clear();
    request = false;
    with_header = false;
    with_body = false;
    with_trailer = false;
    scheme = false;
    host = false;
    port = false;
    path = false;
    query = false;
    fragment = false;
}

uint32_t NHttpIpsOption::hash() const
{
    uint32_t a = IpsOption::hash();
    uint32_t b = (uint32_t)inspect_section;
    uint32_t c = sub_id >> 32;
    uint32_t d = sub_id & 0xFFFFFFFF;
    uint32_t e = form >> 32;
    uint32_t f = form & 0xFFFFFFFF;
    mix(a,b,c);
    mix(d,e,f);
    mix(a,c,f);
    finalize(a,c,f);
    return f;
}

bool NHttpIpsOption::operator==(const IpsOption& ips) const
{
    const NHttpIpsOption& nhio = static_cast<const NHttpIpsOption&>(ips);
    return IpsOption::operator==(ips) &&
           inspect_section == nhio.inspect_section &&
           sub_id == nhio.sub_id &&
           form == nhio.form;
}

int NHttpIpsOption::eval(Cursor& c, Packet* p)
{
    Profile profile(NHttpCursorModule::http_ps[psi]);

    if (!p->flow || !p->flow->gadget)
        return DETECTION_OPTION_NO_MATCH;

    if (NHttpInspect::get_latest_is() != inspect_section)
    {
        // It is OK to provide a body buffer during the detection section. If there actually is
        // a body buffer available then the detection section must also be the first body section.
        if (! ((inspect_section == IS_BODY) && (NHttpInspect::get_latest_is() == IS_DETECTION)) )
            return DETECTION_OPTION_NO_MATCH;
    }

    InspectionBuffer hb;

    if (! ((NHttpInspect*)(p->flow->gadget))->
           nhttp_get_buf((unsigned)buffer_index, sub_id, form, nullptr, hb))
        return DETECTION_OPTION_NO_MATCH;

    c.set(key, hb.data, hb.len);

    return DETECTION_OPTION_MATCH;
}

//-------------------------------------------------------------------------
// http_uri
//-------------------------------------------------------------------------

static const Parameter http_uri_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
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
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_URI, CAT_SET_KEY, PSI_URI,
        http_uri_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_client_body
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_client_body"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the request body"

static Module* client_body_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_CLIENT_BODY, CAT_SET_BODY,
        PSI_CLIENT_BODY);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_method
//-------------------------------------------------------------------------

static const Parameter http_method_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_method"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP request method"

static Module* method_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_METHOD, CAT_SET_OTHER, PSI_METHOD,
        http_method_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_cookie
//-------------------------------------------------------------------------

static const Parameter http_cookie_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the cookie from the request message even when examining the response" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_cookie"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP cookie"

static Module* cookie_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_COOKIE, CAT_SET_OTHER, PSI_COOKIE,
        http_cookie_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_code
//-------------------------------------------------------------------------

static const Parameter http_stat_code_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_stat_code"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP status code"

static Module* stat_code_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_STAT_CODE, CAT_SET_OTHER,
        PSI_STAT_CODE, http_stat_code_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_msg
//-------------------------------------------------------------------------

static const Parameter http_stat_msg_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_stat_msg"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the HTTP status message"

static Module* stat_msg_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_STAT_MSG, CAT_SET_OTHER,
        PSI_STAT_MSG, http_stat_msg_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_uri
//-------------------------------------------------------------------------

static const Parameter http_raw_uri_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
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
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_URI, CAT_SET_OTHER,
        PSI_RAW_URI, http_raw_uri_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_header
//-------------------------------------------------------------------------

static const Parameter http_raw_header_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the headers from the request message even when examining the response" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_header"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized headers"

static Module* raw_header_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_HEADER, CAT_SET_OTHER,
        PSI_RAW_HEADER, http_raw_header_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_cookie
//-------------------------------------------------------------------------

static const Parameter http_raw_cookie_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the cookie from the request message even when examining the response" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_cookie"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized cookie"

static Module* raw_cookie_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_COOKIE, CAT_SET_OTHER,
        PSI_RAW_COOKIE, http_raw_cookie_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_version
//-------------------------------------------------------------------------

static const Parameter http_version_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the version from the request message even when examining the response" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_version"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the version buffer"

static Module* version_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_VERSION, CAT_SET_OTHER,
        PSI_VERSION, http_version_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
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
        "Restrict to given header. Header name is case insensitive." },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the headers from the request message even when examining the response" },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_header"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the normalized headers"

static Module* header_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_HEADER, CAT_SET_HEADER,
        PSI_HEADER, http_header_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_trailer
//-------------------------------------------------------------------------

static const Parameter http_trailer_params[] =
{
    { "field", Parameter::PT_STRING, nullptr, nullptr, "restrict to given trailer" },
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the trailers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP response message headers (must be combined with request)"
        },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body (must be combined with request)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_trailer"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the normalized trailers"

static Module* trailer_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_TRAILER, CAT_SET_HEADER,
        PSI_TRAILER, http_trailer_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_trailer
//-------------------------------------------------------------------------

static const Parameter http_raw_trailer_params[] =
{
    { "request", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Match against the trailers from the request message even when examining the response" },
    { "with_header", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP response message headers (must be combined with request)"
        },
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP response message body (must be combined with request)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_trailer"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized trailers"

static Module* raw_trailer_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_TRAILER, CAT_SET_OTHER,
        PSI_RAW_TRAILER, http_raw_trailer_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_request
//-------------------------------------------------------------------------

static const Parameter http_raw_request_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_request"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized request line"

static Module* raw_request_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_REQUEST, CAT_SET_OTHER,
        PSI_RAW_REQUEST, http_raw_request_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_status
//-------------------------------------------------------------------------

static const Parameter http_raw_status_params[] =
{
    { "with_body", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message body" },
    { "with_trailer", Parameter::PT_IMPLIED, nullptr, nullptr,
        "Parts of this rule examine HTTP message trailers" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#undef IPS_OPT
#define IPS_OPT "http_raw_status"
#undef IPS_HELP
#define IPS_HELP "rule option to set the detection cursor to the unnormalized status line"

static Module* raw_status_mod_ctor()
{
    return new NHttpCursorModule(IPS_OPT, IPS_HELP, NHTTP_BUFFER_RAW_STATUS, CAT_SET_OTHER,
        PSI_RAW_STATUS, http_raw_status_params);
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
        NHttpCursorModule::mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    NHttpIpsOption::opt_ctor,
    NHttpIpsOption::opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &uri_api.base,
    &client_body_api.base,
    &method_api.base,
    &cookie_api.base,
    &stat_code_api.base,
    &stat_msg_api.base,
    &raw_uri_api.base,
    &raw_header_api.base,
    &raw_cookie_api.base,
    &version_api.base,
    &header_api.base,
    &trailer_api.base,
    &raw_trailer_api.base,
    &raw_request_api.base,
    &raw_status_api.base,
    nullptr
};

