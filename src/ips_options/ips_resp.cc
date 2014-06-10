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

#define MOD_NAME "sp_resp3"     /* plugin name */

#define RESP_RST_SND  0x01
#define RESP_RST_RCV  0x02
#define RESP_UNR_NET  0x04
#define RESP_UNR_HOST 0x08
#define RESP_UNR_PORT 0x10

#define RESP_RST (RESP_RST_SND|RESP_RST_RCV)
#define RESP_UNR (RESP_UNR_NET|RESP_UNR_HOST|RESP_UNR_PORT)

static const char* s_name = "resp";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats resp3PerfStats;

static PreprocStats* rsp_get_profile(const char* key)
{
    if ( !strcmp(key, "resp3") )
        return &resp3PerfStats;

    return nullptr;
}
#endif

// instance data
typedef struct {
    uint32_t mask;
} Resp3_Data;

class RespondOption : public IpsOption
{
public:
    RespondOption(Resp3_Data* c) :
        IpsOption(s_name)
    { config = c; };

    ~RespondOption()
    { delete config; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;
    void action(Packet*);

private:
    Resp3_Data* config;
};

static void Resp3_Send(Packet*, void*);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t RespondOption::hash() const
{
    uint32_t a,b,c;

    a = config->mask;
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
    const Resp3_Data *left = config;
    const Resp3_Data *right = rhs.config;

    if (left->mask == right->mask)
        return true;

    return false;
}

void RespondOption::action(Packet*)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(resp3PerfStats);

    Active_QueueResponse(Resp3_Send, config);

    PREPROC_PROFILE_END(resp3PerfStats);
}

//--------------------------------------------------------------------
// core functions
//--------------------------------------------------------------------

static void Resp3_Send (Packet* p, void* pv)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(resp3PerfStats);

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
    PREPROC_PROFILE_END(resp3PerfStats);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static int resp_parse(char* type)
{
    char* *toks;
    uint32_t flags = 0;
    int num_toks = 0, i;

    if ( type )
        toks = mSplit(type, ",", 6, &num_toks, 0);
    else
        ParseError("%s: missing resp modifier", MOD_NAME);

    i = 0;
    while (i < num_toks)
    {
        if ( !strcasecmp(toks[i], "reset_source") ||
             !strcasecmp(toks[i], "rst_snd") )
        {
            flags |= RESP_RST_SND;
            i++;
        }
        else if ( !strcasecmp(toks[i], "reset_dest") ||
                  !strcasecmp(toks[i], "rst_rcv") )
        {
            flags |= RESP_RST_RCV;
            i++;
        }
        else if ( !strcasecmp(toks[i], "reset_both") ||
                  !strcasecmp(toks[i], "rst_all") )
        {
            flags |= (RESP_RST_RCV | RESP_RST_SND);
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_net"))
        {
            flags |= RESP_UNR_NET;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_host"))
        {
            flags |= RESP_UNR_HOST;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_port"))
        {
            flags |= RESP_UNR_PORT;
            i++;
        }
        else if (!strcasecmp(toks[i], "icmp_all"))
        {
            flags |= (RESP_UNR_NET | RESP_UNR_HOST | RESP_UNR_PORT);
            i++;
        }
        else
            ParseError("%s: invalid resp modifier: %s", MOD_NAME, toks[i]);
    }

    mSplitFree(&toks, num_toks);

    if ( !flags )
        ParseError("%s: invalid resp configuration: %s",
            MOD_NAME, "no response specified");

    return flags;
}

static IpsOption* resp_ctor(
    SnortConfig*, char* data, OptTreeNode* otn)
{
    Resp3_Data* rd = (Resp3_Data*)SnortAlloc(sizeof(*rd));
    rd->mask = resp_parse(data);

    RespondOption* opt = new RespondOption(rd);
    
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

#ifdef PERF_PROFILING
    RegisterOtnProfile("resp3", &resp3PerfStats, rsp_get_profile);
#endif
}

static const IpsApi resp_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
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

