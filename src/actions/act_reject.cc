//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
//--------------------------------------------------------------------------
/*
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
 */

// act_reject.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"

using namespace snort;

#define REJ_RST_SRC  0x01
#define REJ_RST_DST  0x02
#define REJ_UNR_NET  0x04
#define REJ_UNR_HOST 0x08
#define REJ_UNR_PORT 0x10

#define REJ_RST_BOTH (REJ_RST_SRC|REJ_RST_DST)
#define REJ_UNR_ALL  (REJ_UNR_NET|REJ_UNR_HOST|REJ_UNR_PORT)

#define s_name "reject"

#define s_help \
    "terminate session with TCP reset or ICMP unreachable"

static THREAD_LOCAL ProfileStats rejPerfStats;

class RejectAction : public IpsAction
{
public:
    RejectAction(uint32_t f) : IpsAction(s_name, ACT_RESET)
    { mask = f; }

    void exec(Packet*) override;

private:
    void send(Packet*);

private:
    uint32_t mask;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

void RejectAction::exec(Packet* p)
{
    Profile profile(rejPerfStats);

    if ( !p->ptrs.ip_api.is_ip() )
        return;

    switch ( p->type() )
    {
    case PktType::TCP:
        if ( !Active::is_reset_candidate(p) )
            return;
        break;

    case PktType::UDP:
    case PktType::ICMP:
    case PktType::IP:
        if ( !Active::is_unreachable_candidate(p) )
            return;
        break;

    default:
        return;
    }

    send(p);
}

void RejectAction::send(Packet* p)
{
    uint32_t flags = 0;

    if ( Active::is_reset_candidate(p) )
        flags |= (mask & REJ_RST_BOTH);

    if ( Active::is_unreachable_candidate(p) )
        flags |= (mask & REJ_UNR_ALL);

    if ( flags & REJ_RST_SRC )
        Active::send_reset(p, 0);

    if ( flags & REJ_RST_DST )
        Active::send_reset(p, ENC_FLAG_FWD);

    if ( flags & REJ_UNR_NET )
        Active::send_unreach(p, snort::UnreachResponse::NET);

    if ( flags & REJ_UNR_HOST )
        Active::send_unreach(p, snort::UnreachResponse::HOST);

    if ( flags & REJ_UNR_PORT )
        Active::send_unreach(p, snort::UnreachResponse::PORT);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "reset", Parameter::PT_ENUM, "source|dest|both", nullptr,
      "send TCP reset to one or both ends" },

    { "control", Parameter::PT_ENUM, "network|host|port|all", nullptr,
      "send ICMP unreachable(s)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RejectModule : public Module
{
public:
    RejectModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &rejPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint32_t flags;
};

bool RejectModule::begin(const char*, int, SnortConfig*)
{
    flags = 0;
    return true;
}

static const int rst[] =
{
    REJ_RST_SRC,
    REJ_RST_DST,
    REJ_RST_BOTH
};

static const int unr[] =
{
    REJ_UNR_PORT,
    REJ_UNR_HOST,
    REJ_UNR_NET,
    REJ_UNR_ALL
};

bool RejectModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("reset") )
        flags |= rst[v.get_long()];

    else if ( v.is("control") )
        flags |= unr[v.get_long()];

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new RejectModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsAction* rej_ctor(Module* p)
{
    RejectModule* m = (RejectModule*)p;
    Active::set_enabled();
    return new RejectAction(m->flags);
}

static void rej_dtor(IpsAction* p)
{
    delete p;
}

static const ActionApi rej_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    Actions::RESET,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    rej_ctor,
    rej_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_reject[] =
#endif
{
    &rej_api.base,
    nullptr
};

