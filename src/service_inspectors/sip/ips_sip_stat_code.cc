//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
//

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip.h"

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "detection/detect.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"

//-------------------------------------------------------------------------
// sip_stat_code
//-------------------------------------------------------------------------

#define s_name "sip_stat_code"
#define s_help \
    "detection option for sip stat code"

static THREAD_LOCAL ProfileStats sipStatCodeRuleOptionPerfStats;

class SipStatCodeOption : public IpsOption
{
public:
    SipStatCodeOption(const SipStatCodeRuleOptData& c) :
        IpsOption(s_name)
    { ssod = c; }

    int eval(Cursor&, Packet*) override;

private:
    SipStatCodeRuleOptData ssod;
};

int SipStatCodeOption::eval(Cursor&, Packet* p)
{
    SIPData* sd;
    SIP_Roptions* ropts;
    uint16_t short_code;
    int i_code;

    PROFILE_VARS;
    MODULE_PROFILE_START(sipStatCodeRuleOptionPerfStats);

    if ((!p->is_tcp() && !p->is_udp()) || !p->flow || !p->dsize)
    {
        MODULE_PROFILE_END(sipStatCodeRuleOptionPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    sd = get_sip_session_data(p->flow);

    if (!sd)
    {
        MODULE_PROFILE_END(sipStatCodeRuleOptionPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    ropts = &sd->ropts;

    if (0 == ropts->status_code)
    {
        MODULE_PROFILE_END(sipStatCodeRuleOptionPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    /*Match the stat code*/
    short_code = ropts->status_code / 100;
    for (i_code = 0; i_code < SIP_NUM_STAT_CODE_MAX; i_code++)
    {
        if ((ssod.stat_codes[i_code] == short_code)||
            (ssod.stat_codes[i_code] == ropts->status_code))
        {
            MODULE_PROFILE_END(sipStatCodeRuleOptionPerfStats);
            return DETECTION_OPTION_MATCH;
        }
    }

    MODULE_PROFILE_END(sipStatCodeRuleOptionPerfStats);

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// sip_stat_code module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "*code", Parameter::PT_INT, "1:999", nullptr,
      "stat code" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SipStatCodeModule : public Module
{
public:
    SipStatCodeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &sipStatCodeRuleOptionPerfStats; }

    SipStatCodeRuleOptData ssod;

private:
    int num_tokens;
};

bool SipStatCodeModule::begin(const char*, int, SnortConfig*)
{
    num_tokens = 0;
    return true;
}

bool SipStatCodeModule::set(const char*, Value& v, SnortConfig*)
{
    unsigned long statCode;
    if (num_tokens < SIP_NUM_STAT_CODE_MAX)
    {
        if ( v.is("*code") )
        {
            statCode = v.get_long();
            if ((statCode > MAX_STAT_CODE) || ((statCode > NUM_OF_RESPONSE_TYPES - 1) &&
                (statCode < MIN_STAT_CODE)))
            {
                ParseError("Status code specified is not a 3 digit number or 1\n");
                return false;
            }
            ssod.stat_codes[num_tokens] = (uint16_t)statCode;
            num_tokens++;
        }
        else
            return false;
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// sip_stat_code api methods
//-------------------------------------------------------------------------

static Module* sip_stat_code_mod_ctor()
{
    return new SipStatCodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* sip_stat_code_ctor(Module* p, OptTreeNode*)
{
    SipStatCodeModule* m = (SipStatCodeModule*)p;
    return new SipStatCodeOption(m->ssod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi sip_stat_code_api =
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
        sip_stat_code_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sip_stat_code_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in sip.cc
const BaseApi* ips_sip_stat_code = &sip_stat_code_api.base;

