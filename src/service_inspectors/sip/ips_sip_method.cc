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

// ips_sip_method.cc
// Authors:
// Hui Cao <huica@cisco.com>
// Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unordered_map>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "sip.h"

using namespace snort;

//-------------------------------------------------------------------------
// sip_method
//-------------------------------------------------------------------------

#define s_name "sip_method"
#define s_help \
    "detection option for sip stat code"

typedef std::unordered_map<std::string, bool> MethodMap; //Method Name => Negated

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
    SipMethodOption(const MethodMap& m) :
        IpsOption(s_name), methods(m) {}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    MethodMap methods;
};

uint32_t SipMethodOption::hash() const
{
    uint32_t a,b,c;

    a = methods.size();
    b = a ? methods.begin()->second : 0;
    c = 0;

    mix_str(a, b, c, get_name());

    for ( auto& m : methods )
        mix_str(a, b, c, m.first.c_str(), m.first.size());

    finalize(a, b, c);

    return c;
}

bool SipMethodOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SipMethodOption& rhs = (const SipMethodOption&)ips;

    return methods == rhs.methods;
}

IpsOption::EvalStatus SipMethodOption::eval(Cursor&, Packet* p)
{
    Profile profile(sipMethodRuleOptionPerfStats);

    if ( !p->flow )
        return NO_MATCH;

    SIPData* sd = get_sip_session_data(p->flow);

    if ( !sd )
        return NO_MATCH;

    SIP_Roptions* ropts = &sd->ropts;

    // Not response
    if ( IsRequest(ropts) && !methods.empty() )
    {
        if ( !ropts->method_data )
            return NO_MATCH;

        //FIXIT-P This should really be evaluated once per request instead of once
        //per rule option evaluation.
        std::string method(ropts->method_data, ropts->method_len);
        std::transform(method.begin(), method.end(), method.begin(), ::toupper);

        bool negated = methods.begin()->second;
        bool match = methods.find(method) != methods.cend(); 

        if ( negated ^ match )
            return MATCH;
    }

    return NO_MATCH;
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

    Usage get_usage() const override
    { return DETECT; }

    MethodMap methods;

private:
    bool negated;
};

bool SipMethodModule::begin(const char*, int, SnortConfig*)
{
    negated = false;
    methods.clear();
    return true;
}

bool SipMethodModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("*method") )
    {
        const char* tok = v.get_string();

        if (tok[0] == '!')
        {
            negated = true;
            tok++;
        }
        else
            negated = false;

        /*Only one method is allowed with !*/
        if ( negated && (!methods.empty()) )
            ParseError("Only one method is allowed with ! for sip_method");

        std::string key = tok;
        std::transform(key.begin(), key.end(), key.begin(), ::toupper);
        methods[key] = negated;
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
    return new SipMethodOption(m->methods);
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

