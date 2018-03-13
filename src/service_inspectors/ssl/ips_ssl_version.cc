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
// ips_ssl_version.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

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
// ssl_version
//-------------------------------------------------------------------------

#define s_name "ssl_version"
#define s_help \
    "detection option for ssl version"

static THREAD_LOCAL ProfileStats sslVersionRuleOptionPerfStats;

struct SslVersionRuleOptionData
{
    int flags;
    int mask;
};

class SslVersionOption : public IpsOption
{
public:
    SslVersionOption(const SslVersionRuleOptionData& c) :
        IpsOption(s_name)
    { svod = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    SslVersionRuleOptionData svod;
};

//-------------------------------------------------------------------------
// ssl_version option
//-------------------------------------------------------------------------

uint32_t SslVersionOption::hash() const
{
    uint32_t a,b,c;

    a = svod.flags;
    b = svod.mask;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool SslVersionOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SslVersionOption& rhs = (const SslVersionOption&)ips;

    if ( (svod.flags == rhs.svod.flags) &&
        (svod.mask == rhs.svod.mask) )
        return true;

    return false;
}

IpsOption::EvalStatus SslVersionOption::eval(Cursor&, Packet* pkt)
{
    Profile profile(sslVersionRuleOptionPerfStats);

    if ( !(pkt->packet_flags & PKT_REBUILT_STREAM) && !pkt->is_full_pdu() )
        return NO_MATCH;

    if (!pkt->flow)
        return NO_MATCH;

    SSLData* sd = get_ssl_session_data(pkt->flow);

    if (!sd)
        return NO_MATCH;

    if ((svod.flags & sd->ssn_flags) ^ svod.mask)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// ssl_version module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "sslv2", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for sslv2" },

    { "sslv3", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for sslv3" },

    { "tls1.0", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for tls1.0" },

    { "tls1.1", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for tls1.1" },

    { "tls1.2", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for tls1.2" },

    { "!sslv2", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not sslv2" },

    { "!sslv3", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not sslv3" },

    { "!tls1.0", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not tls1.0" },

    { "!tls1.1", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not tls1.1" },

    { "!tls1.2", Parameter::PT_IMPLIED, nullptr, nullptr,
      "check for records that are not tls1.2" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SslVersionModule : public Module
{
public:
    SslVersionModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &sslVersionRuleOptionPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    SslVersionRuleOptionData svod;
};

bool SslVersionModule::begin(const char*, int, SnortConfig*)
{
    svod.flags = 0;
    svod.mask = 0;
    return true;
}

bool SslVersionModule::set(const char*, Value& v, SnortConfig*)
{

    if ( v.is("sslv2") )
        svod.flags |= SSL_VER_SSLV2_FLAG;

    else if ( v.is("sslv3") )
        svod.flags |= SSL_VER_SSLV3_FLAG;

    else if ( v.is("tls1.0") )
        svod.flags |= SSL_VER_TLS10_FLAG;

    else if ( v.is("tls1.1") )
        svod.flags |= SSL_VER_TLS11_FLAG;

    else if ( v.is("tls1.2") )
        svod.flags |= SSL_VER_TLS12_FLAG;

    else if ( v.is("!sslv2") )
    {
        svod.flags |= SSL_VER_SSLV2_FLAG;
        svod.mask |= SSL_VER_SSLV2_FLAG;
    }
    else if ( v.is("!sslv3") )
    {
        svod.flags |= SSL_VER_SSLV3_FLAG;
        svod.mask |= SSL_VER_SSLV3_FLAG;
    }
    else if ( v.is("!tls1.0") )
    {
        svod.flags |= SSL_VER_TLS10_FLAG;
        svod.mask |= SSL_VER_TLS10_FLAG;
    }
    else if ( v.is("!tls1.1") )
    {
        svod.flags |= SSL_VER_TLS11_FLAG;
        svod.mask |= SSL_VER_TLS11_FLAG;
    }
    else if ( v.is("!tls1.2") )
    {
        svod.flags |= SSL_VER_TLS12_FLAG;
        svod.mask |= SSL_VER_TLS12_FLAG;
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// ssl_version api methods
//-------------------------------------------------------------------------

static Module* ssl_version_mod_ctor()
{
    return new SslVersionModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ssl_version_ctor(Module* p, OptTreeNode*)
{
    SslVersionModule* m = (SslVersionModule*)p;
    return new SslVersionOption(m->svod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ssl_version_api =
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
        ssl_version_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ssl_version_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_ssl_version = &ssl_version_api.base;

