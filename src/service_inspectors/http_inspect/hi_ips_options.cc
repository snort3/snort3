/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "util.h"
#include "snort_debug.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/ips_option.h"
#include "framework/cursor.h"

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static const char* s_name = "http_ips";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats httpIpsPerfStats;

static PreprocStats* hi_ips_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &httpIpsPerfStats;

    return nullptr;
}
#endif

static void hi_ips_dtor(IpsOption* p)
{
    delete p;
}

static void hi_ips_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &httpIpsPerfStats, hi_ips_get_profile);
#endif
}

//-------------------------------------------------------------------------
// generic buffer stuffer
//-------------------------------------------------------------------------

class HttpIpsOption : public IpsOption
{
public:
    HttpIpsOption(const char* s, HTTP_BUFFER b) : IpsOption(s)
    { key = s; type = b; };

    int eval(Cursor&, Packet*);
private:
    const char* key;
    HTTP_BUFFER type;
};

int HttpIpsOption::eval(Cursor& c, Packet*)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(httpIpsPerfStats);

    int rval;
    const HttpBuffer* hb = GetHttpBuffer(type);

    if ( !hb )
        rval = DETECTION_OPTION_MATCH;
    else
    {
        c.set(key, hb->buf, hb->length);
        rval = DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(httpIpsPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// http_uri
//-------------------------------------------------------------------------

static IpsOption* http_uri_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_uri");

    return new HttpIpsOption("http_uri", HTTP_BUFFER_URI);
}

static const IpsApi http_uri_api =
{
    {
        PT_IPS_OPTION,
        "http_uri",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_uri_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_header
//-------------------------------------------------------------------------

static IpsOption* http_header_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_header");

    return new HttpIpsOption("http_header", HTTP_BUFFER_HEADER);
}

static const IpsApi http_header_api =
{
    {
        PT_IPS_OPTION,
        "http_header",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_header_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_client_body
//-------------------------------------------------------------------------

static IpsOption* http_client_body_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_client_body");

    return new HttpIpsOption("http_client_body", HTTP_BUFFER_CLIENT_BODY);
}

static const IpsApi http_client_body_api =
{
    {
        PT_IPS_OPTION,
        "http_client_body",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_client_body_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_method
//-------------------------------------------------------------------------

static IpsOption* http_method_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_method");

    return new HttpIpsOption("http_method", HTTP_BUFFER_METHOD);
}

static const IpsApi http_method_api =
{
    {
        PT_IPS_OPTION,
        "http_method",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_method_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_cookie
//-------------------------------------------------------------------------

static IpsOption* http_cookie_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_cookie");

    return new HttpIpsOption("http_cookie", HTTP_BUFFER_COOKIE);
}

static const IpsApi http_cookie_api =
{
    {
        PT_IPS_OPTION,
        "http_cookie",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_cookie_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_code
//-------------------------------------------------------------------------

static IpsOption* http_stat_code_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_stat_code");

    return new HttpIpsOption("http_stat_code", HTTP_BUFFER_STAT_CODE);
}

static const IpsApi http_stat_code_api =
{
    {
        PT_IPS_OPTION,
        "http_stat_code",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_stat_code_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_msg
//-------------------------------------------------------------------------

static IpsOption* http_stat_msg_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_stat_msg");

    return new HttpIpsOption("http_stat_msg", HTTP_BUFFER_STAT_MSG);
}

static const IpsApi http_stat_msg_api =
{
    {
        PT_IPS_OPTION,
        "http_stat_msg",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_stat_msg_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_uri
//-------------------------------------------------------------------------

static IpsOption* http_raw_uri_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_raw_uri");

    return new HttpIpsOption("http_raw_uri", HTTP_BUFFER_RAW_URI);
}

static const IpsApi http_raw_uri_api =
{
    {
        PT_IPS_OPTION,
        "http_raw_uri",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_raw_uri_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_header
//-------------------------------------------------------------------------

static IpsOption* http_raw_header_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_raw_header");

    return new HttpIpsOption("http_raw_header", HTTP_BUFFER_RAW_HEADER);
}

static const IpsApi http_raw_header_api =
{
    {
        PT_IPS_OPTION,
        "http_raw_header",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_raw_header_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_cookie
//-------------------------------------------------------------------------

static IpsOption* http_raw_cookie_ctor(
    SnortConfig*, char* data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("%s takes no arguments", "http_raw_cookie");

    return new HttpIpsOption("http_raw_cookie", HTTP_BUFFER_RAW_COOKIE);
}

static const IpsApi http_raw_cookie_api =
{
    {
        PT_IPS_OPTION,
        "http_raw_cookie",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    hi_ips_ginit,
    nullptr,
    nullptr,
    nullptr,
    http_raw_cookie_ctor,
    hi_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &http_uri_api.base,
    &http_header_api.base,
    &http_client_body_api.base,
    &http_method_api.base,
    &http_cookie_api.base,
    &http_stat_code_api.base,
    &http_stat_msg_api.base,
    &http_raw_uri_api.base,
    &http_raw_header_api.base,
    &http_raw_cookie_api.base,
    nullptr
};
#else
const BaseApi* ips_http_uri = &http_uri_api.base;
const BaseApi* ips_http_header = &http_header_api.base;
const BaseApi* ips_http_client_body = &http_client_body_api.base;
const BaseApi* ips_http_method = &http_method_api.base;
const BaseApi* ips_http_cookie = &http_cookie_api.base;
const BaseApi* ips_http_stat_code = &http_stat_code_api.base;
const BaseApi* ips_http_stat_msg = &http_stat_msg_api.base;
const BaseApi* ips_http_raw_uri = &http_raw_uri_api.base;
const BaseApi* ips_http_raw_header = &http_raw_header_api.base;
const BaseApi* ips_http_raw_cookie = &http_raw_cookie_api.base;
#endif

