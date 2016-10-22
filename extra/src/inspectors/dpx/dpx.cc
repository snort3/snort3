//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// dpx.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#define DPX_GID 256
#define DPX_SID 1

static const char* s_name = "dpx";
static const char* s_help = "dynamic inspector example";

static THREAD_LOCAL ProfileStats dpxPerfStats;

static THREAD_LOCAL SimpleStats dpxstats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Dpx : public Inspector
{
public:
    Dpx(uint16_t port, uint16_t max);

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    uint16_t port;
    uint16_t max;
};

Dpx::Dpx(uint16_t p, uint16_t m)
{
    port = p;
    max = m;
}

void Dpx::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
}

void Dpx::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->is_udp());

    if ( p->ptrs.dp == port && p->dsize > max )
        DetectionEngine::queue_event(DPX_GID, DPX_SID);

    ++dpxstats.total_packets;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter dpx_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port to check" },

    { "max", Parameter::PT_INT, "0:65535", "0",
      "maximum payload before alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dpx_rules[] =
{
    { DPX_SID, "too much data sent to port" },
    { 0, nullptr }
};

class DpxModule : public Module
{
public:
    DpxModule() : Module(s_name, s_help, dpx_params)
    { }

    unsigned get_gid() const override
    { return DPX_GID; }

    const RuleMap* get_rules() const override
    { return dpx_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&dpxstats; }

    ProfileStats* get_profile() const override
    { return &dpxPerfStats; }

    bool set(const char*, Value& v, SnortConfig*) override;

public:
    uint16_t port;
    uint16_t max;
};

bool DpxModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("port") )
        port = v.get_long();

    else if ( v.is("max") )
        max = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DpxModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* dpx_ctor(Module* m)
{
    DpxModule* mod = (DpxModule*)m;
    return new Dpx(mod->port, mod->max);
}

static void dpx_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi dpx_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_NETWORK,
    (uint16_t)PktType::UDP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dpx_ctor,
    dpx_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dpx_api.base,
    nullptr
};

