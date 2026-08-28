//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// osi_session_decode_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../osi_session_decode.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TpktAppliSearchStateType tpkt_search_from_osi_pres_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

TpktAppliSearchStateType tpkt_search_from_osi_session_layer(Cursor*, bool)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;

FlowData::FlowData(unsigned u) : id(u) { }
FlowData::~FlowData() = default;

Flow::~Flow() { }
FlowDataStore::~FlowDataStore() { }
}

unsigned TpktFlowData::inspector_id = 0;
TpktFlowData::TpktFlowData() : snort::FlowData(inspector_id) { }
TpktFlowData::~TpktFlowData() = default;

static snort::Packet fake_packet(false);
static snort::Flow fake_flow;
static TpktFlowData fake_flow_data;

namespace snort
{
Packet* DetectionEngine::get_current_packet()
{
    fake_packet.flow = &fake_flow;
    return &fake_packet;
}

FlowData* FlowDataStore::get(unsigned) const
{ return &fake_flow_data; }
}

uint32_t get_max_loops(const Cursor*const)
{ return 0xFFFF; }

uint32_t get_max_pos(const Cursor*, uint32_t idx, uint32_t length)
{ return idx + length; }

uint32_t get_tpkt_work_budget()
{ return 0xFFFF; }

uint16_t mock_charge_calls = 0;
void charge_tpkt_work_budget()
{ mock_charge_calls++; }

TEST_GROUP(osi_session_decode_test)
{
    void setup() override
    {
        mock_charge_calls = 0;
    }

    void teardown() override
    {
    }
};

TEST(osi_session_decode_test, resolve_spdu_parameter_unknown_type)
{
    const uint8_t data[] = { 0x77, 0x01, 0xAA }; // unknown SPDU parameter type (0x77) 

    Cursor cur;
    cur.set("test", data, sizeof(data));

    OsiSessionHdr hdr;
    hdr.spdu_type = OSI_SESSION_SPDU__CN;
    hdr.length    = sizeof(data);

    TpktAppliSearchStateType res = resolve_spdu_parameter(&cur, &hdr);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL((unsigned)sizeof(data), cur.get_pos());
}

TEST(osi_session_decode_test, tpkt_internal_search_from_osi_session_layer_charge_spdu_cn)
{
    uint8_t data[16] = { 0 };
    data[0] = OSI_SESSION_SPDU__CN;   // session spdu_type
    data[1] = 0x0A;                   // session length (non-zero, <= buffer size)
    data[2] = 0x77;                   // unknown SPDU parameter type

    Cursor cur;
    cur.set("test", data, sizeof(data));

    TpktAppliSearchStateType res = tpkt_internal_search_from_osi_session_layer(&cur, false);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL(1, mock_charge_calls);
}

TEST(osi_session_decode_test, tpkt_internal_search_from_osi_session_layer_charge_spdu_ac)
{
    uint8_t data[16] = { 0 };
    data[0] = OSI_SESSION_SPDU__AC;   // session spdu_type
    data[1] = 0x0A;                   // session length (non-zero, <= buffer size)
    data[2] = 0x77;                   // unknown SPDU parameter type

    Cursor cur;
    cur.set("test", data, sizeof(data));

    TpktAppliSearchStateType res = tpkt_internal_search_from_osi_session_layer(&cur, false);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL(1, mock_charge_calls);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
