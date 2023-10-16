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

// iec104.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus.cc (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm.cc (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iec104.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "iec104_decode.h"
#include "iec104_module.h"
#include "iec104_paf.h"

using namespace snort;

THREAD_LOCAL Iec104Stats iec104_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned Iec104FlowData::inspector_id = 0;

void Iec104FlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

Iec104FlowData::Iec104FlowData() :
    FlowData(inspector_id)
{
    iec104_stats.concurrent_sessions++;
    if (iec104_stats.max_concurrent_sessions < iec104_stats.concurrent_sessions)
    {
        iec104_stats.max_concurrent_sessions = iec104_stats.concurrent_sessions;
    }
}

Iec104FlowData::~Iec104FlowData()
{
    assert(iec104_stats.concurrent_sessions > 0);
    iec104_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Iec104: public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    uint32_t get_message_type(uint32_t version, const char* name);
    uint32_t get_info_type(uint32_t version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    {
        return new Iec104Splitter(c2s);
    }
};

void Iec104::eval(Packet* p)
{
    Profile profile(iec104_prof);

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    Iec104FlowData* iec104fd = (Iec104FlowData*) p->flow->get_flow_data(Iec104FlowData::inspector_id);

    if (!p->is_full_pdu())
    {
        if (iec104fd)
        {
            iec104fd->reset();
        }

        // If a packet is rebuilt, but not a full PDU, then it's garbage that
        // got flushed at the end of a stream.
        if (p->packet_flags & (PKT_REBUILT_STREAM | PKT_PDU_HEAD))
        {
            DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_LENGTH);
        }

        return;
    }

    if (!iec104fd)
    {
        iec104fd = new Iec104FlowData;
        p->flow->set_flow_data(iec104fd);
        iec104_stats.sessions++;
    }

    // verify that the reported message length is at least the minimum size
    if ((p->data[1] < IEC104_MIN_APCI_LEN))
    {
        DetectionEngine::queue_event(GID_IEC104, IEC104_BAD_LENGTH);
    }

    // update stats
    iec104_stats.frames++;

    // When pipelined Iec104 PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if (!Iec104Decode(p, iec104fd))
    {
        iec104fd->reset();
    }
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new Iec104Module;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void iec104_init()
{
    Iec104FlowData::init();
}

static Inspector* iec104_ctor(Module*)
{
    return new Iec104;
}

static void iec104_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const InspectApi iec104_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IEC104_NAME,
        IEC104_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr,
    "iec104",
    iec104_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    iec104_ctor,
    iec104_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// BaseApi for each rule option
extern const BaseApi* ips_iec104_asdu_func;
extern const BaseApi* ips_iec104_apci_type;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_iec104[] =
#endif
{
    &iec104_api.base,
    ips_iec104_asdu_func,
    ips_iec104_apci_type,
    nullptr
};

