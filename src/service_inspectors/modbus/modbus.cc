//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// modbus.cc author Russ Combs <rucombs@cisco.com>

#include "modbus.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "events/event_queue.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"

#include "modbus_decode.h"
#include "modbus_module.h"
#include "modbus_paf.h"

THREAD_LOCAL ModbusStats modbus_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned ModbusFlowData::flow_id = 0;

void ModbusFlowData::init()
{
    flow_id = FlowData::get_flow_id();
}

ModbusFlowData::ModbusFlowData() : FlowData(flow_id)
{
    reset();
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Modbus : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet*) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);

    StreamSplitter* get_splitter(bool c2s) override
    { return new ModbusSplitter(c2s); }
};

void Modbus::eval(Packet* p)
{
    Profile profile(modbus_prof);

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    ModbusFlowData* mfd =
        (ModbusFlowData*)p->flow->get_application_data(ModbusFlowData::flow_id);

    if ( !p->is_full_pdu() )
    {
        if ( mfd )
            mfd->reset();

        // If a packet is rebuilt, but not a full PDU, then it's garbage that
        // got flushed at the end of a stream.
        if ( p->packet_flags & (PKT_REBUILT_STREAM|PKT_PDU_HEAD) )
            SnortEventqAdd(GID_MODBUS, MODBUS_BAD_LENGTH);

        return;
    }

    if ( !mfd )
    {
        mfd = new ModbusFlowData;
        p->flow->set_application_data(mfd);
        modbus_stats.sessions++;
    }

    // When pipelined Modbus PDUs appear in a single TCP segment, the
    // detection engine caches the results of the rule options after
    // evaluating on the first PDU. Setting this flag stops the caching.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    if ( !ModbusDecode(p) )
        mfd->reset();
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ModbusModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void modbus_init()
{
    ModbusFlowData::init();
}

static Inspector* modbus_ctor(Module*)
{
    return new Modbus;
}

static void modbus_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const InspectApi modbus_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MODBUS_NAME,
        MODBUS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr,
    "modbus",
    modbus_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    modbus_ctor,
    modbus_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
extern const BaseApi* ips_modbus_data;
extern const BaseApi* ips_modbus_func;
extern const BaseApi* ips_modbus_unit;

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &modbus_api.base,
    ips_modbus_data,
    ips_modbus_func,
    ips_modbus_unit,
    nullptr
};
#else
const BaseApi* sin_modbus = &modbus_api.base;
#endif

