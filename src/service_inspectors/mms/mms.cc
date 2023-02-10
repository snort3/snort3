//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// mms.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus.cc (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm.cc (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mms.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mms_decode.h"
#include "mms_module.h"
#include "mms_splitter.h"
#include "util_tpkt.h"

using namespace snort;

THREAD_LOCAL MmsStats mms_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned MmsFlowData::inspector_id = 0;

void MmsFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

MmsFlowData::MmsFlowData() :
    FlowData(inspector_id)
{
    mms_stats.concurrent_sessions++;
    if (mms_stats.max_concurrent_sessions < mms_stats.concurrent_sessions)
    {
        mms_stats.max_concurrent_sessions = mms_stats.concurrent_sessions;
    }
}

MmsFlowData::~MmsFlowData()
{
    assert(mms_stats.concurrent_sessions > 0);
    mms_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Mms : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    uint32_t get_message_type(uint32_t version, const char* name);
    uint32_t get_info_type(uint32_t version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    {
        return new MmsSplitter(c2s);
    }
};

void Mms::eval(Packet* p)
{
    Profile profile(mms_prof);

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    MmsFlowData* mmsfd = (MmsFlowData*)p->flow->get_flow_data(MmsFlowData::inspector_id);

    // not including any checks for a full PDU as we're not guaranteed to
    // have one with the available pipelining options to get to MMS

    if (!mmsfd)
    {
        mmsfd = new MmsFlowData;
        p->flow->set_flow_data(mmsfd);
        mms_stats.sessions++;
    }

    // update stats
    mms_stats.frames++;

    // When pipelined MMS PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if (!mms_decode(p, mmsfd))
    {
        mmsfd->reset();
    }
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MmsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void mms_init()
{
    MmsFlowData::init();
    TpktFlowData::init();
}

static Inspector* mms_ctor(Module*)
{
    return new Mms;
}

static void mms_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* mms_bufs[] =
{
    "mms_data",
    nullptr
};

static const InspectApi mms_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MMS_NAME,
        MMS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    mms_bufs,
    "mms",
    mms_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    mms_ctor,
    mms_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// BaseApi for each rule option
extern const BaseApi* ips_mms_data;
extern const BaseApi* ips_mms_func;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi * sin_mms[] =
#endif
{
    &mms_api.base,
    ips_mms_data,
    ips_mms_func,
    nullptr
};

