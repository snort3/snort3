/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License Version 2 as published by
 * the Free Software Foundation.  You may not use, modify or distribute this
 * program under any other version of the GNU General Public License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 ****************************************************************************/
/* Snort sp_resp3 Detection Plugin
 *
 * Perform flexible response on packets matching conditions specified in Snort
 * rules.
 *
 * Shutdown hostile network connections by injecting TCP resets or ICMP
 * unreachable packets.
 *
 * flexresp3 is derived from flexresp and flexresp2.  It includes all
 * configuration options from those modules and has these differences:
 *
 * - injects packets with correct encapsulations (doesn't assume
 * eth+ip+icmp/tcp).
 *
 * - uses the wire packet as a prototype, not the packet generating the alert
 * (which may be reassembled or otherwise generated internally with only the
 * headers required for logging).
 *
 * - queues the injection action so that it is taken only once after detection
 * regardless of multiple resp3 rules firing.
 *
 * - uses the same encoding and injection mechanism as active_response and/or
 * reject actions.
 *
 * - bypasses sequence strafing in inline mode.
 *
 * - if a resp3 rule is also a drop rule, the drop processing takes precedence.
 */

// @file    sp_respond3.c
// @author  Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "protocols/packet.h"
#include "managers/packet_manager.h"
#include "detection/detection_defines.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "fpdetect.h"
#include "packet_io/active.h"
#include "sfhashfcn.h"
#include "sfxhash.h"
#include "snort.h"
#include "util.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

#define RESP_RST_SND  0x01
#define RESP_RST_RCV  0x02
#define RESP_UNR_NET  0x04
#define RESP_UNR_HOST 0x08
#define RESP_UNR_PORT 0x10

#define RESP_RST (RESP_RST_SND|RESP_RST_RCV)
#define RESP_UNR (RESP_UNR_NET|RESP_UNR_HOST|RESP_UNR_PORT)

static const char* s_name = "resp";

static THREAD_LOCAL ProfileStats resp3PerfStats;

// instance data
struct Resp3_Data
{
    uint32_t mask;
};

class RespondOption : public IpsOption
{
public:
    RespondOption(uint32_t f) :
        IpsOption(s_name)
    { config.mask = f; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;
    void action(Packet*);

private:
    Resp3_Data config;
};

static void Resp3_Send(Packet*, void*);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t RespondOption::hash() const
{
    uint32_t a,b,c;

    a = config.mask;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool RespondOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    RespondOption& rhs = (RespondOption&)ips;
    const Resp3_Data *left = &config;
    const Resp3_Data *right = &rhs.config;

    if (left->mask == right->mask)
        return true;

    return false;
}

void RespondOption::action(Packet*)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(resp3PerfStats);

    Active_QueueResponse(Resp3_Send, &config);

    MODULE_PROFILE_END(resp3PerfStats);
}

//--------------------------------------------------------------------
// core functions
//--------------------------------------------------------------------

static void Resp3_Send (Packet* p, void* pv)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(resp3PerfStats);

    Resp3_Data* rd = (Resp3_Data*)pv;
    uint32_t flags = 0;

    if ( Active_IsRSTCandidate(p) )
        flags |= (rd->mask & RESP_RST);

    if ( Active_IsUNRCandidate(p) )
        flags |= (rd->mask & RESP_UNR);

    if ( flags & RESP_RST_SND )
        Active_SendReset(p, 0);

    if ( flags & RESP_RST_RCV )
        Active_SendReset(p, ENC_FLAG_FWD);

    if ( flags & RESP_UNR_NET )
        Active_SendUnreach(p, ENC_UNR_NET);

    if ( flags & RESP_UNR_HOST )
        Active_SendUnreach(p, ENC_UNR_HOST);

    if ( flags & RESP_UNR_PORT )
        Active_SendUnreach(p, ENC_UNR_PORT);

    Active_IgnoreSession(p);
    MODULE_PROFILE_END(resp3PerfStats);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter resp_params[] =
{
    { "reset_source", Parameter::PT_STRING, nullptr, nullptr,
      "reset sender" },

    { "rst_snd", Parameter::PT_STRING, nullptr, nullptr,
      "reset sender" },

    { "reset_dest", Parameter::PT_STRING, nullptr, nullptr,
      "reset receiver" },

    { "rst_rcv", Parameter::PT_STRING, nullptr, nullptr,
      "reset receiver" },

    { "reset_both", Parameter::PT_STRING, nullptr, nullptr,
      "reset both sender and receiver" },

    { "rst_all", Parameter::PT_STRING, nullptr, nullptr,
      "reset both sender and receiver" },

    { "icmp_net", Parameter::PT_STRING, nullptr, nullptr,
      "send icmp network unreachable to sender" },

    { "icmp_host", Parameter::PT_STRING, nullptr, nullptr,
      "send icmp host unreachable to sender" },

    { "icmp_port", Parameter::PT_STRING, nullptr, nullptr,
      "send icmp port unreachable to sender" },

    { "icmp_all", Parameter::PT_STRING, nullptr, nullptr,
      "send icmp net, host, and port unreachable to sender" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RespModule : public Module
{
public:
    RespModule() : Module(s_name, resp_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &resp3PerfStats; };

    uint32_t flags;
};

bool RespModule::begin(const char*, int, SnortConfig*)
{
    flags = 0;
    return true;
}

bool RespModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("reset_source") || v.is("rst_snd") )
        flags |= RESP_RST_SND;

    else if ( v.is("reset_dest") || v.is("rst_rcv") )
        flags |= RESP_RST_RCV;

    else if ( v.is("reset_both") || v.is("rst_all") )
        flags |= (RESP_RST_RCV | RESP_RST_SND);

    else if ( v.is("icmp_net") )
        flags |= RESP_UNR_NET;

    else if ( v.is("icmp_host") )
        flags |= RESP_UNR_HOST;

    else if ( v.is("icmp_port") )
        flags |= RESP_UNR_PORT;

    else if ( v.is("icmp_all") )
        flags |= (RESP_UNR_NET | RESP_UNR_HOST | RESP_UNR_PORT);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new RespModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* resp_ctor(Module* p, OptTreeNode* otn)
{
    RespModule* m = (RespModule*)p;
    RespondOption* opt = new RespondOption(m->flags);
    
    if ( otn_set_agent(otn, opt) )
        return opt;

    delete opt;
    ParseError("At most one action per rule is allowed");
    return nullptr;
}

static void resp_dtor(IpsOption* p)
{
    delete p;
}

static void resp_ginit(SnortConfig*)
{
    Active_SetEnabled(1);
}

static const IpsApi resp_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_ACTION,
    1, 0,
    resp_ginit,
    nullptr,
    nullptr,
    nullptr,
    resp_ctor,
    resp_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &resp_api.base,
    nullptr
};
#else
const BaseApi* ips_resp = &resp_api.base;
#endif

