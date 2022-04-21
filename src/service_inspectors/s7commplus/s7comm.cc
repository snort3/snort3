//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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

// s7comm.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "s7comm.h"

#include "events/event_queue.h"
#include "detection/detection_engine.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "s7comm_decode.h"
#include "s7comm_module.h"
#include "s7comm_paf.h"

using namespace snort;

THREAD_LOCAL S7commplusStats s7commplus_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned S7commplusFlowData::inspector_id = 0;

void S7commplusFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

S7commplusFlowData::S7commplusFlowData() : FlowData(inspector_id)
{
    s7commplus_stats.concurrent_sessions++;
    if (s7commplus_stats.max_concurrent_sessions < s7commplus_stats.concurrent_sessions)
        s7commplus_stats.max_concurrent_sessions = s7commplus_stats.concurrent_sessions;
}

S7commplusFlowData::~S7commplusFlowData()
{
    assert(s7commplus_stats.concurrent_sessions > 0);
    s7commplus_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class S7commplus : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    { return new S7commplusSplitter(c2s); }
};

void S7commplus::eval(Packet* p)
{
    Profile profile(s7commplus_prof);

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    S7commplusFlowData* mfd =
        (S7commplusFlowData*)p->flow->get_flow_data(S7commplusFlowData::inspector_id);

    if ( !p->is_full_pdu() )
    {
        if ( mfd )
            mfd->reset();

        // If a packet is rebuilt, but not a full PDU, then it's garbage that
        // got flushed at the end of a stream.
        if ( p->packet_flags & (PKT_REBUILT_STREAM|PKT_PDU_HEAD) )
            DetectionEngine::queue_event(GID_S7COMMPLUS, S7COMMPLUS_BAD_LENGTH);

        return;
    }

    if ( !mfd )
    {
        mfd = new S7commplusFlowData;
        p->flow->set_flow_data(mfd);
        s7commplus_stats.sessions++;
    }

    // When pipelined S7commplus PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if ( !S7commplusDecode(p, mfd))
        mfd->reset();
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new S7commplusModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void s7commplus_init()
{
    S7commplusFlowData::init();
}

static Inspector* s7commplus_ctor(Module*)
{
    return new S7commplus;
}

static void s7commplus_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* s7commplus_bufs[] =
{
    "s7commplus_content",
    nullptr
};

static const InspectApi s7commplus_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S7COMMPLUS_NAME,
        S7COMMPLUS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    s7commplus_bufs,
    "s7commplus",
    s7commplus_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    s7commplus_ctor,
    s7commplus_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_s7commplus_opcode;
extern const BaseApi* ips_s7commplus_func;
extern const BaseApi* ips_s7commplus_content;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_s7commplus[] =
#endif
{
    &s7commplus_api.base,
    ips_s7commplus_opcode,
    ips_s7commplus_func,
    ips_s7commplus_content,
    nullptr
};

