/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// ips_http.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "protocols/packet.h"
#include "snort_debug.h"
#include "snort.h"
#include "profiler.h"
#include "flow/flow.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/cursor.h"
#include "framework/inspector.h"
#include "framework/module.h"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class HttpCursorModule : public Module
{
public:
    HttpCursorModule(const char* s, const char* h, ProfileStats& p) :
        Module(s, h), ps(p) { };

    ProfileStats* get_profile() const override
    { return &ps; };

    ProfileStats& ps;
};

static void mod_dtor(Module* m)
{
    delete m;
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

//-------------------------------------------------------------------------
// generic buffer stuffer
//-------------------------------------------------------------------------

class HttpIpsOption : public IpsOption
{
public:
    HttpIpsOption(
        const char* s, ProfileStats& p, CursorActionType c = CAT_SET_OTHER) :
        IpsOption(s), ps(p)
    { key = s; cat = c; };

    CursorActionType get_cursor_type() const override
    { return cat; };

    int eval(Cursor&, Packet*) override;
private:
    const char* key;
    CursorActionType cat;
    ProfileStats& ps;
};

int HttpIpsOption::eval(Cursor& c, Packet* p)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(ps);

    int rval;
    InspectionBuffer hb;

    if ( !p->flow || !p->flow->gadget )
        rval = DETECTION_OPTION_NO_MATCH;

    // FIXIT-P cache id at parse time for runtime use
    else if ( !p->flow->gadget->get_buf(key, p, hb) )
        rval = DETECTION_OPTION_NO_MATCH;

    else
    {
        c.set(key, hb.data, hb.len);
        rval = DETECTION_OPTION_MATCH;
    }

    MODULE_PROFILE_END(ps);
    return rval;
}

//-------------------------------------------------------------------------
// http_uri
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_uri"

#define uri_help \
    "rule option to set the detection cursor to the normalized URI buffer"

static THREAD_LOCAL ProfileStats uri_ps;

static Module* uri_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, uri_help, uri_ps);
}

static IpsOption* uri_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, uri_ps, CAT_SET_COMMAND);
}

static const IpsApi uri_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        uri_help,
        IPSAPI_PLUGIN_V0,
        0,
        uri_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    uri_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_client_body
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_client_body"

#define cb_help \
    "rule option to set the detection cursor to the request body"

static THREAD_LOCAL ProfileStats cb_ps;

static Module* client_body_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, cb_help, cb_ps);
}

static IpsOption* client_body_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, cb_ps, CAT_SET_BODY);
}

static const IpsApi client_body_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        cb_help,
        IPSAPI_PLUGIN_V0,
        0,
        client_body_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    client_body_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_method
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_method"

#define meth_help \
    "rule option to set the detection cursor to the HTTP request method"

static THREAD_LOCAL ProfileStats meth_ps;

static Module* method_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, meth_help, meth_ps);
}

static IpsOption* method_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, meth_ps);
}

static const IpsApi method_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        meth_help,
        IPSAPI_PLUGIN_V0,
        0,
        method_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    method_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_cookie
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_cookie"

#define cookie_help  \
    "rule option to set the detection cursor to the HTTP cookie"

static THREAD_LOCAL ProfileStats cookie_ps;

static Module* cookie_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, cookie_help, cookie_ps);
}

static IpsOption* cookie_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, cookie_ps);
}

static const IpsApi cookie_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        cookie_help,
        IPSAPI_PLUGIN_V0,
        0,
        cookie_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cookie_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_code
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_stat_code"

#define stat_code_help  \
    "rule option to set the detection cursor to the HTTP status code"

static THREAD_LOCAL ProfileStats stat_code_ps;

static Module* stat_code_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, stat_code_help, stat_code_ps);
}

static IpsOption* stat_code_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, stat_code_ps);
}

static const IpsApi stat_code_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        stat_code_help,
        IPSAPI_PLUGIN_V0,
        0,
        stat_code_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    stat_code_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_stat_msg
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_stat_msg"

#define stat_msg_help  \
    "rule option to set the detection cursor to the HTTP status message"

static THREAD_LOCAL ProfileStats stat_msg_ps;

static Module* stat_msg_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, stat_msg_help, stat_msg_ps);
}

static IpsOption* stat_msg_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, stat_msg_ps);
}

static const IpsApi stat_msg_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        stat_msg_help,
        IPSAPI_PLUGIN_V0,
        0,
        stat_msg_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    stat_msg_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_uri
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_raw_uri"

#define raw_uri_help  \
    "rule option to set the detection cursor to the unnormalized URI"

static THREAD_LOCAL ProfileStats raw_uri_ps;

static Module* raw_uri_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, raw_uri_help, raw_uri_ps);
}

static IpsOption* raw_uri_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, raw_uri_ps);
}

static const IpsApi raw_uri_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        raw_uri_help,
        IPSAPI_PLUGIN_V0,
        0,
        raw_uri_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    raw_uri_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_header
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_raw_header"

#define raw_header_help  \
    "rule option to set the detection cursor to the unnormalized headers"

static THREAD_LOCAL ProfileStats raw_header_ps;

static Module* raw_header_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, raw_header_help, raw_header_ps);
}

static IpsOption* raw_header_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, raw_header_ps);
}

static const IpsApi raw_header_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        raw_header_help,
        IPSAPI_PLUGIN_V0,
        0,
        raw_header_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    raw_header_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// http_raw_cookie
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "http_raw_cookie"

#define raw_cookie_help  \
    "rule option to set the detection cursor to the unnormalized cookie"

static THREAD_LOCAL ProfileStats raw_cookie_ps;

static Module* raw_cookie_mod_ctor()
{
    return new HttpCursorModule(IPS_OPT, raw_cookie_help, raw_cookie_ps);
}

static IpsOption* raw_cookie_opt_ctor(Module*, OptTreeNode*)
{
    return new HttpIpsOption(IPS_OPT, raw_cookie_ps);
}

static const IpsApi raw_cookie_api =
{
    {
        PT_IPS_OPTION,
        IPS_OPT,
        raw_cookie_help,
        IPSAPI_PLUGIN_V0,
        0,
        raw_cookie_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    raw_cookie_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

#ifdef BUILDING_SO
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
    nullptr
};
#else
const BaseApi* ips_http_uri = &uri_api.base;
const BaseApi* ips_http_client_body = &client_body_api.base;
const BaseApi* ips_http_method = &method_api.base;
const BaseApi* ips_http_cookie = &cookie_api.base;
const BaseApi* ips_http_stat_code = &stat_code_api.base;
const BaseApi* ips_http_stat_msg = &stat_msg_api.base;
const BaseApi* ips_http_raw_uri = &raw_uri_api.base;
const BaseApi* ips_http_raw_header = &raw_header_api.base;
const BaseApi* ips_http_raw_cookie = &raw_cookie_api.base;
#endif

