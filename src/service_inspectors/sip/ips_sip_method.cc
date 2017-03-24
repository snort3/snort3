//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// ips_sip_method.cc
// Authors:
// Hui Cao <huica@cisco.com>
// Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/sfhashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "sip.h"

//-------------------------------------------------------------------------
// sip_method
//-------------------------------------------------------------------------

#define s_name "sip_method"
#define s_help \
    "detection option for sip stat code"

static THREAD_LOCAL ProfileStats sipMethodRuleOptionPerfStats;

static inline bool IsRequest(SIP_Roptions* ropts)
{
    if (ropts->status_code)
        return false;
    else
        return true;
}

class SipMethodOption : public IpsOption
{
public:
    SipMethodOption(const SipMethodRuleOptData& c) :
        IpsOption(s_name)
    { smod = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    int eval(Cursor&, Packet*) override;

private:
    SipMethodRuleOptData smod;
};

uint32_t SipMethodOption::hash() const
{
    uint32_t a,b,c;

    a = smod.flags;
    b = smod.mask;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool SipMethodOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SipMethodOption& rhs = (SipMethodOption&)ips;

    if ( (smod.flags == rhs.smod.flags) &&
        (smod.mask == rhs.smod.mask) )
        return true;

    return false;
}

int SipMethodOption::eval(Cursor&, Packet* p)
{
    Profile profile(sipMethodRuleOptionPerfStats);

    if ((!p->is_tcp() && !p->is_udp()) || !p->flow || !p->dsize)
        return DETECTION_OPTION_NO_MATCH;

    SIPData* sd = get_sip_session_data(p->flow);

    if (!sd)
        return DETECTION_OPTION_NO_MATCH;

    SIP_Roptions* ropts = &sd->ropts;

    // Not response
    uint32_t methodFlag = 1 << (ropts->methodFlag - 1);

    if (IsRequest(ropts) && ((smod.flags & methodFlag) ^ smod.mask))
        return DETECTION_OPTION_MATCH;

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// sip_method module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "*method", Parameter::PT_STRING, nullptr, nullptr,
      "sip method" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SipMethodModule : public Module
{
public:
    SipMethodModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &sipMethodRuleOptionPerfStats; }

    SipMethodRuleOptData smod;

private:
    int num_tokens;
    bool negated;
};

bool SipMethodModule::begin(const char*, int, SnortConfig*)
{
    num_tokens = 0;
    negated = false;
    smod.flags = smod.mask = 0;
    return true;
}

bool SipMethodModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("*method") )
    {
        char* tok = (char*)v.get_string();
        SIPMethodNode *method = NULL;

        if (tok[0] == '!')
        {
            negated = true;
            tok++;
        }
        else
            negated = false;

        /*Only one method is allowed with !*/
        if (negated && (++num_tokens > 1))
            ParseError("Only one method is allowed with ! for sip_method");

        method = add_sip_method(tok);

        if(!method)
        {
            ParseError("Failed to add a new method to sip_method");
            return false;
        }

        smod.flags |= 1 << (method->methodFlag - 1);

        if (negated)
            smod.mask |= 1 << (method->methodFlag - 1);
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// sip_method api methods
//-------------------------------------------------------------------------

static Module* sip_method_mod_ctor()
{
    return new SipMethodModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* sip_method_ctor(Module* p, OptTreeNode*)
{
    SipMethodModule* m = (SipMethodModule*)p;
    return new SipMethodOption(m->smod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi sip_method_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        sip_method_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sip_method_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in sip.cc
const BaseApi* ips_sip_method = &sip_method_api.base;

