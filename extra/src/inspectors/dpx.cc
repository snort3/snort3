//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "time/profiler.h"
#include "utils/stats.h"

#define DPX_GID 256
#define DPX_SID 1
#define DPX_REV 1
#define DPX_PRI 1
#define DPX_MSG "too much data sent to port"

#if 0
#define PP_DPX 10000

#ifdef DEBUG
#define DEBUG_DPX DEBUG_PP_EXP
#endif
#endif

static const char* s_name = "dpx";
static const char* s_help = "dynamic inspector example";

static THREAD_LOCAL ProfileStats dpxPerfStats;

static THREAD_LOCAL SimpleStats dpxstats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class DpxPH : public Inspector
{
public:
    DpxPH();

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    uint16_t port;
    uint16_t max;
};

DpxPH::DpxPH()
{
    port = 68;
    max = 300;
}

void DpxPH::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
}

void DpxPH::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->is_udp());

    if ( p->ptrs.dp == port && p->dsize > max )
        SnortEventqAdd(DPX_GID, DPX_SID);

    ++dpxstats.total_packets;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

class DpxModule : public Module
{
public:
    DpxModule() : Module(s_name, s_help)
    { }

    const PegInfo* get_pegs() const
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&dpxstats; }

    ProfileStats* get_profile() const override
    { return &dpxPerfStats; }
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Inspector* dpx_ctor(Module*)
{
    return new DpxPH;
}

static void dpx_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi dpx_api
{
    {
        PT_INSPECTOR,
        s_name,
        s_help,
        INSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    IT_NETWORK,
    PROTO_BIT__UDP,
    nullptr, // service
    nullptr, // contents
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

