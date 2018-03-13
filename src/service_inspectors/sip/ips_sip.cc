//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// Authors:
// Hui Cao <huica@cisco.com>
// Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "sip.h"

using namespace snort;

enum SipIdx
{
    SIP_HEADER, SIP_BODY, SIP_MAX
};

static THREAD_LOCAL std::array<ProfileStats, SIP_MAX> sip_ps;
// static THREAD_LOCAL ProfileStats sip_ps[SIP_MAX];

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class SipCursorModule : public Module
{
public:
    SipCursorModule(const char* s, const char* h, SipIdx psi) :
        Module(s, h) { idx = psi; }

    ProfileStats* get_profile() const override
    { return &sip_ps[idx]; }

    Usage get_usage() const override
    { return DETECT; }

private:
    SipIdx idx;
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

class SipIpsOption : public IpsOption
{
public:
    SipIpsOption(
        const char* s, SipIdx psi, CursorActionType c = CAT_SET_OTHER) :
        IpsOption(s, RULE_OPTION_TYPE_BUFFER_SET)
    { key = s; cat = c; idx = psi; }

    CursorActionType get_cursor_type() const override
    { return cat; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    const char* key;
    CursorActionType cat;
    SipIdx idx;
};

IpsOption::EvalStatus SipIpsOption::eval(Cursor& c, Packet* p)
{
    Profile profile(sip_ps[idx]);

    if ((!p->is_tcp() && !p->is_udp()) || !p->flow || !p->dsize)
        return NO_MATCH;

    // FIXIT-P cache id at parse time for runtime use
    SIPData* sd = get_sip_session_data(p->flow);

    if (!sd)
        return NO_MATCH;

    SIP_Roptions* ropts = &sd->ropts;
    const uint8_t* data = nullptr;
    unsigned len = 0;

    switch (idx)
    {
    case SIP_HEADER:
        data = ropts->header_data;
        len = ropts->header_len;
        break;
    case SIP_BODY:
        data = ropts->body_data;
        len = ropts->body_len;
        break;
    default:
        break;
    }

    if (data != nullptr)
    {
        c.set(key, data, len);
        return MATCH;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// sip_header
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "sip_header"

#define header_help \
    "rule option to set the detection cursor to the SIP header buffer"

static Module* header_mod_ctor()
{
    return new SipCursorModule(IPS_OPT, header_help, SIP_HEADER);
}

static IpsOption* header_opt_ctor(Module*, OptTreeNode*)
{
    return new SipIpsOption(IPS_OPT, SIP_HEADER, CAT_SET_HEADER);
}

static const IpsApi header_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        header_help,
        header_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    header_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// sip_body
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "sip_body"

#define cb_help \
    "rule option to set the detection cursor to the request body"

static Module* body_mod_ctor()
{
    return new SipCursorModule(IPS_OPT, cb_help, SIP_BODY);
}

static IpsOption* body_opt_ctor(Module*, OptTreeNode*)
{
    return new SipIpsOption(IPS_OPT, SIP_BODY, CAT_SET_BODY);
}

static const IpsApi body_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        cb_help,
        body_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    body_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

// added to snort_plugins in sip.cc
const BaseApi* ips_sip_header = &header_api.base;
const BaseApi* ips_sip_body = &body_api.base;

