//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/ipv4_options.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "ipopts"

static THREAD_LOCAL ProfileStats ipOptionPerfStats;

struct IpOptionData
{
    ip::IPOptionCodes ip_option;
    uint8_t any_flag;
};

class IpOptOption : public IpsOption
{
public:
    IpOptOption(const IpOptionData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    IpOptionData* get_data()
    { return &config; }

private:
    IpOptionData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpOptOption::hash() const
{
    uint32_t a,b,c;
    const IpOptionData* data = &config;

    a = (uint32_t)data->ip_option;
    b = data->any_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IpOptOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const IpOptOption& rhs = (const IpOptOption&)ips;
    const IpOptionData* left = &config;
    const IpOptionData* right = &rhs.config;

    if ((left->ip_option == right->ip_option) &&
        (left->any_flag == right->any_flag))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus IpOptOption::eval(Cursor&, Packet* p)
{
    Profile profile(ipOptionPerfStats);

    if ( !p->is_ip4() )
        // if error occurred while ip header
        // was processed, return 0 automatically.
        return NO_MATCH;

    const ip::IP4Hdr* const ip4h = p->ptrs.ip_api.get_ip4h();
    const uint8_t option_len = ip4h->get_opt_len();

    if ((config.any_flag == 1) && (option_len > 0))
    {
        return MATCH;
    }

    ip::IpOptionIterator iter(ip4h, p);

    for ( const ip::IpOptions& opt : iter)
    {
        if (config.ip_option == opt.code)
            return MATCH;

    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void ipopts_parse(const char* data, IpOptionData* ds_ptr)
{
    if (strcasecmp(data, "rr") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::RR;
    }
    else if (strcasecmp(data, "eol") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::EOL;
    }
    else if (strcasecmp(data, "nop") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::NOP;
    }
    else if (strcasecmp(data, "ts") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::TS;
    }
    else if (strcasecmp(data, "esec") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::ESEC;
    }
    else if (strcasecmp(data, "sec") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::SECURITY;
    }
    else if (strcasecmp(data, "lsrr") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::LSRR;
    }
    else if (strcasecmp(data, "lsrre") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::LSRR_E;
    }
    else if (strcasecmp(data, "satid") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::SATID;
    }
    else if (strcasecmp(data, "ssrr") == 0)
    {
        ds_ptr->ip_option = ip::IPOptionCodes::SSRR;
    }
    else if (strcasecmp(data, "any") == 0)
    {
        ds_ptr->ip_option = static_cast<ip::IPOptionCodes>(0);
        ds_ptr->any_flag = 1;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_opts \
    "rr|eol|nop|ts|sec|esec|lsrr|lsrre|ssrr|satid|any"

static const Parameter s_params[] =
{
    { "~opt", Parameter::PT_SELECT, s_opts, nullptr,
      "output format" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check for IP options"

class IpOptModule : public Module
{
public:
    IpOptModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &ipOptionPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    IpOptionData data;
};

bool IpOptModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool IpOptModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~opt") )
        ipopts_parse(v.get_string(), &data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IpOptModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ipopts_ctor(Module* p, OptTreeNode*)
{
    IpOptModule* m = (IpOptModule*)p;
    return new IpOptOption(m->data);
}

static void ipopts_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ipopts_api =
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
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ipopts_ctor,
    ipopts_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_ipopts[] =
#endif
{
    &ipopts_api.base,
    nullptr
};

