/****************************************************************************
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

// ips_stream_size.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_session.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "detection/detect.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"

enum SsodOp
{
    SSOD_EQ = 1,
    SSOD_NE,
    SSOD_LT,
    SSOD_GT,
    SSOD_LE,
    SSOD_GE,
    SSOD_MAX
};

struct StreamSizeOptionData
{
    SsodOp opcode;
    uint32_t size;
    char direction;

    bool compare(uint32_t, uint32_t);
};

bool StreamSizeOptionData::compare(uint32_t size1, uint32_t size2)
{
    switch (opcode)
    {
    case SSOD_EQ:
        return (size1 == size2);

    case SSOD_NE:
        return (size1 != size2);

    case SSOD_LT:
        return (size1 < size2);

    case SSOD_GT:
        return (size1 > size2);

    case SSOD_LE:
        return (size1 <= size2);

    case SSOD_GE:
        return (size1 >= size2);

    default:
        break;
    }
    return false;
}

//-------------------------------------------------------------------------
// stream_size
//-------------------------------------------------------------------------

static const char* s_name = "stream_size";
static const char* s_help =
    "detection option for stream size checking";

static THREAD_LOCAL ProfileStats streamSizePerfStats;

class SizeOption : public IpsOption
{
public:
    SizeOption(const StreamSizeOptionData& c) :
        IpsOption(s_name)
    { ssod = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    StreamSizeOptionData ssod;
};

//-------------------------------------------------------------------------
// stream_size option
//-------------------------------------------------------------------------

uint32_t SizeOption::hash() const
{
    uint32_t a,b,c;

    a = ssod.direction;
    b = ssod.opcode;
    c = ssod.size;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool SizeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SizeOption& rhs = (SizeOption&)ips;

    if ( (ssod.direction == rhs.ssod.direction) &&
         (ssod.opcode == rhs.ssod.opcode) &&
         (ssod.size == rhs.ssod.size) )
        return true;

    return false;
}

int SizeOption::eval(Cursor&, Packet* pkt)
{
    if (!pkt->flow || !pkt->tcph)
        return DETECTION_OPTION_NO_MATCH;

    PROFILE_VARS;
    MODULE_PROFILE_START(streamSizePerfStats);

    Flow *lwssn = (Flow*)pkt->flow;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    uint32_t client_size;
    uint32_t server_size;

    if (tcpssn->client.l_nxt_seq > tcpssn->client.isn)
    {
        /* the normal case... */
        client_size = tcpssn->client.l_nxt_seq - tcpssn->client.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        client_size = tcpssn->client.isn - tcpssn->client.l_nxt_seq;
    }
    if (tcpssn->server.l_nxt_seq > tcpssn->server.isn)
    {
        /* the normal case... */
        server_size = tcpssn->server.l_nxt_seq - tcpssn->server.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        server_size = tcpssn->server.isn - tcpssn->server.l_nxt_seq;
    }

    int result = DETECTION_OPTION_NO_MATCH;

    switch (ssod.direction)
    {
    case SSN_DIR_CLIENT:
        if ( ssod.compare(client_size, ssod.size) )
            result = DETECTION_OPTION_MATCH;
        break;

    case SSN_DIR_SERVER:
        if ( ssod.compare(server_size, ssod.size) )
            result = DETECTION_OPTION_MATCH;
        break;

    case SSN_DIR_NONE: /* overloaded.  really, its an 'either' */
        if ( ssod.compare(client_size, ssod.size) ||
             ssod.compare(server_size, ssod.size) )
        {
            result = DETECTION_OPTION_MATCH;
        }
        break;

    case SSN_DIR_BOTH:
        if ( ssod.compare(client_size, ssod.size) &&
             ssod.compare(server_size, ssod.size) )
        {
            result = DETECTION_OPTION_MATCH;
        }
        break;

    default:
        break;
    }
    MODULE_PROFILE_END(streamSizePerfStats);
    return result;
}

//-------------------------------------------------------------------------
// stream_size module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "*direction", Parameter::PT_ENUM, "either|client|server|both", nullptr,
      "compare applies to the given direction(s)" },

    { "*operator", Parameter::PT_ENUM, "= | != | < | > | <= | >=", nullptr,
      "how to compare" },

    { "*size", Parameter::PT_INT, nullptr, nullptr,
      "size for comparison" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SizeModule : public Module
{
public:
    SizeModule() : Module(s_name, s_help, s_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &streamSizePerfStats; };

    StreamSizeOptionData ssod;
};

bool SizeModule::begin(const char*, int, SnortConfig*)
{
    ssod.direction = 0;
    ssod.opcode = SSOD_EQ;
    ssod.size = 0;
    return true;
}

bool SizeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("*direction") )
        ssod.direction = v.get_long();

    else if ( v.is("*operator") )
        ssod.opcode = (SsodOp)(v.get_long() + 1);

    else if ( v.is("*size") )
        ssod.size = 0;

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
    return new SizeOption(m->ssod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi size_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        s_help,
        IPSAPI_PLUGIN_V0,
        0,
        size_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    size_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_stream_size = &size_api.base;

