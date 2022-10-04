//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"

#include "actions.h"

using namespace snort;

#define s_name "reject"

#define s_help \
    "terminate session with TCP reset or ICMP unreachable"

enum
{
    REJ_NONE     = 0x00,
    REJ_RST_SRC  = 0x01,
    REJ_RST_DST  = 0x02,
    REJ_UNR_NET  = 0x04,
    REJ_UNR_HOST = 0x08,
    REJ_UNR_PORT = 0x10,
    REJ_UNR_FWD  = 0x20,
    REJ_RST_BOTH = (REJ_RST_SRC | REJ_RST_DST),
    REJ_UNR_ALL  = (REJ_UNR_NET | REJ_UNR_HOST | REJ_UNR_PORT | REJ_UNR_FWD)
};

THREAD_LOCAL ProfileStats rejPerfStats;

//-------------------------------------------------------------------------
// active action
//-------------------------------------------------------------------------

class RejectActiveAction : public ActiveAction
{
public:
    RejectActiveAction(uint32_t f) : ActiveAction (ActionPriority::AP_RESET) , mask(f) { }
    void delayed_exec(Packet*) override;

private:
    uint32_t mask;
};

void RejectActiveAction::delayed_exec(Packet* p)
{
    if ( !p->ptrs.ip_api.is_ip() )
        return;

    Active* act = p->active;

    Profile profile(rejPerfStats);

    switch ( p->type() )
    {
    case PktType::TCP:
        if ( !act->is_reset_candidate(p) )
            return;
        break;

    case PktType::UDP:
    case PktType::ICMP:
    case PktType::IP:
        if ( !act->is_unreachable_candidate(p) )
            return;
        break;

    default:
        return;
    }

    uint32_t flags = 0;

    if ( act->is_reset_candidate(p) )
        flags |= (mask & REJ_RST_BOTH);

    if ( act->is_unreachable_candidate(p) )
        flags |= (mask & REJ_UNR_ALL);

    if ( flags & REJ_RST_SRC )
        act->send_reset(p, 0);

    if ( flags & REJ_RST_DST )
        act->send_reset(p, ENC_FLAG_FWD);

    if ( flags & REJ_UNR_FWD )
        act->send_unreach(p, UnreachResponse::FWD);

    if ( flags & REJ_UNR_NET )
        act->send_unreach(p, UnreachResponse::NET);

    if ( flags & REJ_UNR_HOST )
        act->send_unreach(p, UnreachResponse::HOST);

    if ( flags & REJ_UNR_PORT )
        act->send_unreach(p, UnreachResponse::PORT);
}

//-------------------------------------------------------------------------
// ips action
//-------------------------------------------------------------------------

class RejectAction : public IpsAction
{
public:
    RejectAction(uint32_t f = REJ_RST_BOTH);

    void exec(Packet*, const OptTreeNode* otn) override;

private:
    RejectActiveAction rej_act_action;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

RejectAction::RejectAction(uint32_t f) : IpsAction(s_name, &rej_act_action) , rej_act_action(f)
{ }

void RejectAction::exec(Packet* p, const OptTreeNode* otn)
{
    p->active->set_delayed_action(Active::ACT_RESET, get_active_action());
    p->active->set_drop_reason("ips");
    p->active->reset_again();
    p->active->update_status(p);

    Actions::alert(p, otn);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "reset", Parameter::PT_ENUM, "none|source|dest|both", "both",
      "send TCP reset to one or both ends" },

    { "control", Parameter::PT_ENUM, "none|network|host|port|forward|all", "none",
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

    uint32_t get_data();

private:
    uint32_t flags;
};

bool RejectModule::begin(const char*, int, SnortConfig*)
{
    flags = 0;
    return true;
}

static const int rst[] =
{
    REJ_NONE,
    REJ_RST_SRC,
    REJ_RST_DST,
    REJ_RST_BOTH
};

static const int unr[] =
{
    REJ_NONE,
    REJ_UNR_NET,
    REJ_UNR_HOST,
    REJ_UNR_PORT,
    REJ_UNR_FWD,
    REJ_UNR_ALL
};

bool RejectModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("reset") )
    {
        flags &= ~REJ_RST_BOTH;
        flags |= rst[v.get_uint8()];
    }

    else if ( v.is("control") )
    {
        flags &= ~REJ_UNR_ALL;
        flags |= unr[v.get_uint8()];
    }

    return true;
}

uint32_t RejectModule::get_data()
{
    return flags;
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
    if ( p )
    {
        RejectModule* m = (RejectModule*)p;
        return new RejectAction(m->get_data());
    }
    else
        return new RejectAction();
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
    IpsAction::IAP_REJECT,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    rej_ctor,
    rej_dtor
};

const BaseApi* act_reject[] =
{
    &rej_api.base,
    nullptr
};

