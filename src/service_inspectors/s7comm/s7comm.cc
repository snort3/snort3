//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

THREAD_LOCAL S7commStats s7comm_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned S7commFlowData::inspector_id = 0;

void S7commFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

S7commFlowData::S7commFlowData() : FlowData(inspector_id)
{
    s7comm_stats.concurrent_sessions++;
    if (s7comm_stats.max_concurrent_sessions < s7comm_stats.concurrent_sessions)
        s7comm_stats.max_concurrent_sessions = s7comm_stats.concurrent_sessions;
}

S7commFlowData::~S7commFlowData()
{
    assert(s7comm_stats.concurrent_sessions > 0);
    s7comm_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class S7comm : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    { return new S7commSplitter(c2s); }
};

void S7comm::eval(Packet* p)
{
    Profile profile(s7comm_prof);   // cppcheck-suppress unreadVariable

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    S7commFlowData* mfd =
        (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    if ( !p->is_full_pdu() )
    {
        if ( mfd )
            mfd->reset();

        // If a packet is rebuilt, but not a full PDU, then it's garbage that
        // got flushed at the end of a stream.
        if ( p->packet_flags & (PKT_REBUILT_STREAM|PKT_PDU_HEAD) )
            DetectionEngine::queue_event(GID_S7COMM, S7COMM_BAD_LENGTH);

        return;
    }

    if ( !mfd )
    {
        mfd = new S7commFlowData;
        p->flow->set_flow_data(mfd);
        s7comm_stats.sessions++;
    }

    // When pipelined S7comm PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if ( !S7commDecode(p, mfd))
        mfd->reset();
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new S7commModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void s7comm_init()
{
    S7commFlowData::init();
}

static Inspector* s7comm_ctor(Module*)
{
    return new S7comm;
}

static void s7comm_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* s7comm_bufs[] =
{
    "s7comm_content",
    nullptr
};

static const InspectApi s7comm_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S7COMM_NAME,
        S7COMM_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    s7comm_bufs,
    "s7comm",
    s7comm_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    s7comm_ctor,
    s7comm_dtor,
    nullptr, // ssn
    nullptr  // reset
};

extern const BaseApi* ips_s7comm_func;
extern const BaseApi* ips_s7comm_content;
extern const BaseApi* ips_s7comm_error_code;
extern const BaseApi* ips_s7comm_error_class;
extern const BaseApi* ips_s7comm_pdu_ref;
extern const BaseApi* ips_s7comm_parameter_length;
extern const BaseApi* ips_s7comm_data_length;
extern const BaseApi* ips_s7comm_function_code;
extern const BaseApi* ips_s7comm_item_count;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_s7comm[] =
#endif
{
    &s7comm_api.base,
    ips_s7comm_func,
    ips_s7comm_content,
    ips_s7comm_error_code,
    ips_s7comm_error_class,
    ips_s7comm_pdu_ref,
    ips_s7comm_parameter_length,
    ips_s7comm_data_length,
    ips_s7comm_function_code,
    ips_s7comm_item_count,
    nullptr
};
