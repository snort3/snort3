//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_stream_size.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/range.h"
#include "hash/hashfcn.h"
#include "profiler/profiler_defs.h"

#include "tcp_session.h"

using namespace snort;

//-------------------------------------------------------------------------
// stream_size
//-------------------------------------------------------------------------

#define s_name "stream_size"
#define s_help \
    "detection option for stream size checking"

static THREAD_LOCAL ProfileStats streamSizePerfStats;

class SizeOption : public IpsOption
{
public:
    SizeOption(const RangeCheck& c, int dir) :
        IpsOption(s_name)
    { ssod = c; direction = dir; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck ssod;
    int direction;
};

//-------------------------------------------------------------------------
// stream_size option
//-------------------------------------------------------------------------

uint32_t SizeOption::hash() const
{
    uint32_t a,b,c;

    a = ssod.op;
    b = ssod.min;
    c = ssod.max;

    mix(a,b,c);

    a = direction;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool SizeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SizeOption& rhs = (const SizeOption&)ips;

    if ( (direction == rhs.direction) && (ssod == rhs.ssod) )
        return true;

    return false;
}

IpsOption::EvalStatus SizeOption::eval(Cursor&, Packet* pkt)
{
    DeepProfile profile(streamSizePerfStats);

    if ( !pkt->flow || pkt->flow->pkt_type != PktType::TCP )
        return NO_MATCH;

    TcpSession* tcpssn = (TcpSession*)pkt->flow->session;

    uint32_t client_size;
    uint32_t server_size;

    if (tcpssn->client.get_snd_nxt() > tcpssn->client.get_iss())
    {
        /* the normal case... */
        client_size = tcpssn->client.get_snd_nxt() - tcpssn->client.get_iss();
    }
    else
    {
        /* the seq num wrapping case... */
        client_size = tcpssn->client.get_iss() - tcpssn->client.get_snd_nxt();
    }

    if (tcpssn->server.get_snd_nxt() > tcpssn->server.get_iss())
    {
        /* the normal case... */
        server_size = tcpssn->server.get_snd_nxt() - tcpssn->server.get_iss();
    }
    else
    {
        /* the seq num wrapping case... */
        server_size = tcpssn->server.get_iss() - tcpssn->server.get_snd_nxt();
    }

    switch ( direction )
    {
    case SSN_DIR_FROM_CLIENT:
        if ( ssod.eval(client_size) )
            return MATCH;
        break;

    case SSN_DIR_FROM_SERVER:
        if ( ssod.eval(server_size) )
            return MATCH;
        break;

    case SSN_DIR_NONE: /* overloaded.  really, its an 'either' */
        if ( ssod.eval(client_size) || ssod.eval(server_size) )
            return MATCH;
        break;

    case SSN_DIR_BOTH:
        if ( ssod.eval(client_size) && ssod.eval(server_size) )
            return MATCH;
        break;

    default:
        break;
    }

    return NO_MATCH;

}

//-------------------------------------------------------------------------
// stream_size module
//-------------------------------------------------------------------------

#define RANGE "0:"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if the stream size is in the given range" },

    { "~direction", Parameter::PT_ENUM, "either|to_server|to_client|both", nullptr,
      "compare applies to the given direction(s)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SizeModule : public Module
{
public:
    SizeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &streamSizePerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck ssod;
    int direction;
};

bool SizeModule::begin(const char*, int, SnortConfig*)
{
    ssod.init();
    direction = 0;
    return true;
}

bool SizeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~range") )
        return ssod.validate(v.get_string(), RANGE);

    else if ( v.is("~direction") )
        direction = v.get_long();

    else
        return false;
    
    return true;
}

//-------------------------------------------------------------------------
// stream_size api methods
//-------------------------------------------------------------------------

static Module* size_mod_ctor()
{
    return new SizeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* size_ctor(Module* p, OptTreeNode*)
{
    SizeModule* m = (SizeModule*)p;
    return new SizeOption(m->ssod, m->direction);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi size_api =
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
        size_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,  // FIXIT-L eventually change to 1 since <> and <=> are supported
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    size_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_stream_size = &size_api.base;

