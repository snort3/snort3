//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_ssl_state.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"

#include "ssl_inspector.h"

using namespace snort;

//-------------------------------------------------------------------------
// ssl_state
//-------------------------------------------------------------------------

#define s_name "ssl_state"
#define s_help \
    "detection option for ssl state"

static THREAD_LOCAL ProfileStats sslStateRuleOptionPerfStats;

struct SslStateRuleOptionData
{
    int flags;
    int mask;
};

class SslStateOption : public IpsOption
{
public:
    SslStateOption(const SslStateRuleOptionData& c) :
        IpsOption(s_name)
    { ssod = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    SslStateRuleOptionData ssod;
};

//-------------------------------------------------------------------------
// ssl_state option
//-------------------------------------------------------------------------

uint32_t SslStateOption::hash() const
{
    uint32_t a,b,c;

    a = ssod.flags;
    b = ssod.mask;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool SslStateOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SslStateOption& rhs = (const SslStateOption&)ips;

    if ( (ssod.flags == rhs.ssod.flags) &&
        (ssod.mask == rhs.ssod.mask) )
        return true;

    return false;
}

IpsOption::EvalStatus SslStateOption::eval(Cursor&, Packet* pkt)
{
    Profile profile(sslStateRuleOptionPerfStats);

    if ( !(pkt->packet_flags & PKT_REBUILT_STREAM) && !pkt->is_full_pdu() )
        return NO_MATCH;

    if (!pkt->flow)
        return NO_MATCH;

    SSLData* sd = get_ssl_session_data(pkt->flow);

    if (!sd)
        return NO_MATCH;

    if ((ssod.flags & sd->ssn_flags) ^ ssod.mask)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// ssl_state module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "client_hello", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for client hello" },

    { "server_hello", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for server hello" },

    { "client_keyx", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for client keyx" },

    { "server_keyx", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for server keyx" },

    { "unknown", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for unknown record" },

    { "!client_hello", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not client hello" },

    { "!server_hello", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not server hello" },

    { "!client_keyx", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not client keyx" },

    { "!server_keyx", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not server keyx" },

    { "!unknown", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not unknown" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SslStateModule : public Module
{
public:
    SslStateModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &sslStateRuleOptionPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    SslStateRuleOptionData ssod;
};

bool SslStateModule::begin(const char*, int, SnortConfig*)
{
    ssod.flags = 0;
    ssod.mask = 0;
    return true;
}

bool SslStateModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("client_hello") )
        ssod.flags |= SSL_CUR_CLIENT_HELLO_FLAG;

    else if ( v.is("server_hello") )
        ssod.flags |= SSL_CUR_SERVER_HELLO_FLAG;

    else if ( v.is("client_keyx") )
        ssod.flags |= SSL_CUR_CLIENT_KEYX_FLAG;

    else if ( v.is("server_keyx") )
        ssod.flags |= SSL_CUR_SERVER_KEYX_FLAG;

    else if ( v.is("unknown") )
        ssod.flags |= SSL_UNKNOWN_FLAG;

    else if ( v.is("!client_hello") )
    {
        ssod.flags |= SSL_CUR_CLIENT_HELLO_FLAG;
        ssod.mask |= SSL_CUR_CLIENT_HELLO_FLAG;
    }
    else if ( v.is("!server_hello") )
    {
        ssod.flags |= SSL_CUR_SERVER_HELLO_FLAG;
        ssod.mask |= SSL_CUR_SERVER_HELLO_FLAG;
    }
    else if ( v.is("!client_keyx") )
    {
        ssod.flags |= SSL_CUR_CLIENT_KEYX_FLAG;
        ssod.mask |= SSL_CUR_CLIENT_KEYX_FLAG;
    }
    else if ( v.is("!server_keyx") )
    {
        ssod.flags |= SSL_CUR_SERVER_KEYX_FLAG;
        ssod.mask |= SSL_CUR_SERVER_KEYX_FLAG;
    }
    else if ( v.is("!unknown") )
    {
        ssod.flags |= SSL_UNKNOWN_FLAG;
        ssod.mask |= SSL_UNKNOWN_FLAG;
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// ssl_state api methods
//-------------------------------------------------------------------------

static Module* ssl_state_mod_ctor()
{
    return new SslStateModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ssl_state_ctor(Module* p, OptTreeNode*)
{
    SslStateModule* m = (SslStateModule*)p;
    return new SslStateOption(m->ssod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ssl_state_api =
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
        ssl_state_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ssl_state_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_ssl_state = &ssl_state_api.base;

