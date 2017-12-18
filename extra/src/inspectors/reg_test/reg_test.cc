//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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
// rti_service.cc author davis mcpherson <davmcphe@cisco.com>

#include <ctime>

#include "flow/expect_cache.h"
#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "pub_sub/expect_events.h"
#include "time/packet_time.h"

static const char* s_name = "reg_test";
static const char* s_help = "The regression test inspector (rti) is used when special packet handling is required for a reg test";

struct RtiStats
{
    PegCount total_packets;
    PegCount retry_requests;
    PegCount retry_packets;
};

const PegInfo rti_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::SUM, "retry_requests", "total retry packets requested" },
    { CountType::SUM, "retry_packets", "total retried packets received" },
    { CountType::END, nullptr, nullptr }
};

static THREAD_LOCAL RtiStats rti_stats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter rti_params[] =
{
    { "test_daq_retry", Parameter::PT_BOOL, nullptr, "true",
        "test daq packet retry feature" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RtiServiceModule : public Module
{
public:
    RtiServiceModule() : Module(s_name, s_help, rti_params)
    { }

    const PegInfo* get_pegs() const override
    { return rti_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&rti_stats; }

    bool set(const char*, Value& v, SnortConfig*) override;

    bool is_test_daq_retry() { return test_daq_retry; }

public:
    bool test_daq_retry = true;
};

bool RtiServiceModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("test_daq_retry") )
        test_daq_retry = v.get_bool();
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------
class RegTestFlowData : public FlowData
{
public:
    RegTestFlowData();
    ~RegTestFlowData() override;
    static void init()
    { inspector_id = FlowData::create_flow_data_id(); }

    void handle_expected(Packet*) override;

public:
    static unsigned inspector_id;
    unsigned test_id;
    static unsigned test_id_counter;
};

unsigned RegTestFlowData::inspector_id = 0;
unsigned RegTestFlowData::test_id_counter = 100;

RegTestFlowData::RegTestFlowData() : FlowData(inspector_id)
{
    test_id = test_id_counter++;
}

RegTestFlowData::~RegTestFlowData()
{
    LogMessage("Reg test: delete flow data, test_id=%d\n", test_id);
}

void RegTestFlowData::handle_expected(Packet*)
{
    LogMessage("Reg test: handle expected, test_id=%d\n", test_id);
}

//-------------------------------------------------------------------------
// event handler stuff
//-------------------------------------------------------------------------
class ExpectEventHandler : public DataHandler
{
public:
    ExpectEventHandler()
    {  }

    void handle(DataEvent&, Flow*) override;
};


void ExpectEventHandler::handle(DataEvent& event, Flow*)
{
    ExpectEvent* expect_event = (ExpectEvent*)&event;
    char cstr[INET6_ADDRSTRLEN], sstr[INET6_ADDRSTRLEN];
    expect_event->get_packet()->flow->client_ip.ntop(cstr, sizeof(cstr));
    expect_event->get_packet()->flow->server_ip.ntop(sstr, sizeof(sstr));
    LogMessage("Reg test: received expect event. packet %s:%d -> %s:%d\n",
        cstr, expect_event->get_packet()->flow->client_port,
        sstr, expect_event->get_packet()->flow->server_port);
    ExpectFlow* flow = expect_event->get_expect_flow();
    RegTestFlowData* fd = (RegTestFlowData*)flow->get_flow_data(RegTestFlowData::inspector_id);
    if (!fd)
    {
        fd = new RegTestFlowData();
        LogMessage("Reg test: created a new flow data, test_id=%d, adding ... ", fd->test_id);
        unsigned added_test_id = fd->test_id;
        flow->add_flow_data(fd);
        fd = (RegTestFlowData*)flow->get_flow_data(RegTestFlowData::inspector_id);
        if (fd && fd->test_id == added_test_id)
            LogMessage("succeed!\n");
        else
            LogMessage("failed!\n");
    }
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class RtiService : public Inspector
{
public:
    RtiService(RtiServiceModule* mod);

    void show(SnortConfig*) override;
    void eval(Packet* p) override;
    bool configure(SnortConfig*) override
    {
        DataBus::subscribe(EXPECT_EVENT_TYPE_EARLY_SESSION_CREATE_KEY, new ExpectEventHandler());
        return true;
    }

private:
    bool test_daq_retry;
    void do_daq_packet_retry_test(Packet* p);
};

RtiService::RtiService(RtiServiceModule* mod)
{
    test_daq_retry = mod->is_test_daq_retry();
    rti_stats.total_packets = 0;
}

void RtiService::eval(Packet* p)
{
    if ( test_daq_retry )
        do_daq_packet_retry_test(p);

    rti_stats.total_packets++;
}

void RtiService::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
}

void RtiService::do_daq_packet_retry_test(Packet* p)
{
    if (p->dsize)
    {
        if (p->data[0] == 'A')
        {
            static bool retry_packet = true;
            static bool expect_retry_packet = false;

            if (retry_packet)
            {
                Active::daq_retry_packet(p);
                retry_packet = false;
                expect_retry_packet = true;
                rti_stats.retry_requests++;
            }
            else if (expect_retry_packet)
            {
                if ( p->pkth->flags & DAQ_PKT_FLAG_RETRY_PACKET )
                {
                    expect_retry_packet = false;
                    rti_stats.retry_packets++;
                }
            }
        }
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------
static void reg_test_init()
{
    RegTestFlowData::init();
}

static Module* mod_ctor()
{ return new RtiServiceModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* rti_ctor(Module* m)
{ return new RtiService((RtiServiceModule*)m); }

static void rti_dtor(Inspector* p)
{ delete p; }

static const InspectApi rti_api
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
    IT_PACKET,
    (uint16_t)PktType::TCP | (uint16_t)PktType::UDP | (uint16_t)PktType::PDU,
    nullptr, // buffers
    s_name,  // service
    reg_test_init, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    rti_ctor,
    rti_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rti_api.base,
    nullptr
};

