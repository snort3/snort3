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

// util_tpkt_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../../util_tpkt.cc"

#include <cstring>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "ber_mock.h"

using namespace snort;

TpktAppliSearchStateType tpkt_internal_search_from_tpkt_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

TpktAppliSearchStateType tpkt_internal_search_from_cotp_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

TpktAppliSearchStateType tpkt_internal_search_from_osi_session_layer(Cursor*, bool)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

TpktAppliSearchStateType tpkt_internal_search_from_osi_pres_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

TpktAppliSearchStateType tpkt_internal_search_from_osi_acse_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;

FlowData::FlowData(unsigned u) : id(u) { }
FlowData::~FlowData() = default;
unsigned FlowData::create_flow_data_id() { return 0; }

Flow::Flow() { }
Flow::~Flow() { }
void FlowStash::reset() { }
FlowDataStore::~FlowDataStore() { }

void FlowDataStore::set(FlowData*) { }
}

// typed globals backing get_next_tpkt_encap_layer's packet/flow/flow-data access;
// returning a stored instance from get() avoids leaking a heap-allocated one
static snort::Packet fake_packet(false);
static snort::Flow fake_flow;
static TpktFlowData fake_flow_data;

namespace snort
{
FlowData* FlowDataStore::get(unsigned) const
{ return &fake_flow_data; }
}

TEST_GROUP(tpkt_work_budget)
{
};

TEST(tpkt_work_budget, reset_sets_budget_to_size_over_smallest_tlv)
{
    const uint8_t data[30] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    reset_tpkt_work_budget(&cur);

    // budget == cursor size / smallest TLV
    CHECK_EQUAL((unsigned)(sizeof(data) / TPKT_SMALLEST_TLV_SIZE), get_tpkt_work_budget());
}

TEST(tpkt_work_budget, charge_decrements_budget_by_one)
{
    const uint8_t data[30] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    reset_tpkt_work_budget(&cur);
    const uint32_t before = get_tpkt_work_budget();

    charge_tpkt_work_budget();

    CHECK_EQUAL(before - 1, get_tpkt_work_budget());
}

TEST(tpkt_work_budget, charge_saturates_at_zero)
{
    const uint8_t data[6] = { 0 };   // budget == 6 / 3 == 2
    Cursor cur;
    cur.set("test", data, sizeof(data));

    reset_tpkt_work_budget(&cur);
    CHECK_EQUAL(2u, get_tpkt_work_budget());

    // charge more times than the budget allows
    for (int i = 0; i < 5; ++i)
        charge_tpkt_work_budget();

    // the budget must clamp at 0 and never underflow / wrap around
    CHECK_EQUAL(0u, get_tpkt_work_budget());
}

TEST_GROUP(get_max_loops)
{
};

TEST(get_max_loops, clamps_to_remaining_budget)
{
    const uint8_t data[30] = { 0 };   // cursor-derived cap == 30 / 3 == 10
    Cursor cur;
    cur.set("test", data, sizeof(data));

    reset_tpkt_work_budget(&cur);
    for (int i = 0; i < 8; ++i)       // spend the budget down to 2
        charge_tpkt_work_budget();

    CHECK_EQUAL(2u, get_tpkt_work_budget());
    // clamped to the remaining budget (2), not the larger cursor cap (10)
    CHECK_EQUAL(2u, get_max_loops(&cur));
}

TEST(get_max_loops, uses_cursor_cap_when_budget_larger)
{
    const uint8_t small[30] = { 0 };  // cursor-derived cap == 10
    Cursor small_cur;
    small_cur.set("small", small, sizeof(small));

    // reset from a much larger cursor so the budget (100) exceeds the cap
    const uint8_t big[300] = { 0 };
    Cursor big_cur;
    big_cur.set("big", big, sizeof(big));
    reset_tpkt_work_budget(&big_cur);

    // the cursor-derived cap is the limiting factor
    CHECK_EQUAL((unsigned)(sizeof(small) / TPKT_SMALLEST_TLV_SIZE), get_max_loops(&small_cur));
}

TEST_GROUP(get_max_pos)
{
};

TEST(get_max_pos, in_bounds_returns_idx_plus_length_minus_one)
{
    const uint8_t data[100] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    // 10 + 20 - 1 == 29, well within the buffer
    CHECK_EQUAL(29u, get_max_pos(&cur, 10, 20));
}

TEST(get_max_pos, oversized_length_clamps_to_cursor_size)
{
    const uint8_t data[100] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    // malformed length far past the buffer must clamp to the size
    CHECK_EQUAL((unsigned)sizeof(data), get_max_pos(&cur, 0, 0xFFFFFFFF));
}

TEST(get_max_pos, zero_length_underflow_clamps_to_cursor_size)
{
    const uint8_t data[100] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    // idx + length - 1 underflows for idx == length == 0; the 64-bit math must not wrap to a small in-bounds value
    CHECK_EQUAL((unsigned)sizeof(data), get_max_pos(&cur, 0, 0));
}

TEST_GROUP(persist_exit_offset_at_end)
{
};

TEST(persist_exit_offset_at_end, client_direction_sets_client_exit_offset)
{
    TpktFlowData tpktfd;

    const uint8_t data[42] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    persist_exit_offset_at_end(&tpktfd, &cur, /*is_from_client*/ true);

    // the client exit offset advances to the end of the available data
    CHECK_EQUAL((unsigned)sizeof(data), tpktfd.ssn_data.client_exit_offset);
    // the server direction is left untouched
    CHECK_EQUAL(0u, tpktfd.ssn_data.server_exit_offset);
}

TEST(persist_exit_offset_at_end, server_direction_sets_server_exit_offset)
{
    TpktFlowData tpktfd;

    const uint8_t data[42] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    persist_exit_offset_at_end(&tpktfd, &cur, /*is_from_client*/ false);

    // the server exit offset advances to the end of the available data
    CHECK_EQUAL((unsigned)sizeof(data), tpktfd.ssn_data.server_exit_offset);
    // the client direction is left untouched
    CHECK_EQUAL(0u, tpktfd.ssn_data.client_exit_offset);
}

TEST_GROUP(get_next_tpkt_encap_layer_exit_offset)
{
    void setup() override
    {
        ber_mock_reset();
        fake_packet.flow = &fake_flow;
        fake_packet.packet_flags = 0;
        fake_flow_data.ssn_data.client_exit_offset = 0;
        fake_flow_data.ssn_data.server_exit_offset = 0;
    }

    void teardown() override
    {
        ber_mock_reset();
    }
};

TEST(get_next_tpkt_encap_layer_exit_offset, no_layer_found_sets_client_exit_offset)
{
    uint8_t data[24];
    memset(data, 0xFF, sizeof(data));   // matches no known encapsulation layer

    Cursor cur;
    cur.set("test", data, sizeof(data));

    fake_packet.packet_flags = PKT_FROM_CLIENT;

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    // no layer is identified, so the client exit offset advances past the data
    CHECK(layer == TPKT_ENCAP_LAYER__NONE);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.client_exit_offset);
    CHECK_EQUAL(0u, fake_flow_data.ssn_data.server_exit_offset);
}

TEST(get_next_tpkt_encap_layer_exit_offset, no_layer_found_sets_server_exit_offset)
{
    uint8_t data[24];
    memset(data, 0xFF, sizeof(data));   // matches no known encapsulation layer

    Cursor cur;
    cur.set("test", data, sizeof(data));

    fake_packet.packet_flags = 0;   // from the server side

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    // no layer is identified, so the server exit offset advances past the data
    CHECK(layer == TPKT_ENCAP_LAYER__NONE);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.server_exit_offset);
    CHECK_EQUAL(0u, fake_flow_data.ssn_data.client_exit_offset);
}

TEST(get_next_tpkt_encap_layer_exit_offset, matched_cotp_layer_persists_exit_offset)
{
    uint8_t data[24] = { 0 };
    // a valid COTP DT DATA header: length 0x02, pdu_type 0x0F, last_data_unit 1
    data[0] = 0x02;
    data[1] = 0xF0;
    data[2] = 0x80;

    Cursor cur;
    cur.set("test", data, sizeof(data));

    fake_packet.packet_flags = PKT_FROM_CLIENT;

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    // a matched layer still persists the exit offset before returning
    CHECK(layer == TPKT_ENCAP_LAYER__COTP);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.client_exit_offset);
}

TEST(get_next_tpkt_encap_layer_exit_offset, matched_osi_session_layer_persists_exit_offset)
{
    uint8_t data[24] = { 0 };
    // a Connect (CN) SPDU with a length that fits within the cursor
    data[0] = OSI_SESSION_SPDU__CN;
    data[1] = 0x01;

    Cursor cur;
    cur.set("test", data, sizeof(data));

    fake_packet.packet_flags = PKT_FROM_CLIENT;

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    CHECK(layer == TPKT_ENCAP_LAYER__OSI_SESSION);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.client_exit_offset);
}

TEST(get_next_tpkt_encap_layer_exit_offset, matched_osi_pres_layer_persists_exit_offset)
{
    uint8_t data[24] = { 0 };

    Cursor cur;
    cur.set("test", data, sizeof(data));

    // an OSI Pres CP/CPA BER tag (0x31) whose header + payload stays within the cursor
    ber_mock_push(0x31, 1, 2);

    fake_packet.packet_flags = 0;   // from the server side

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    CHECK(layer == TPKT_ENCAP_LAYER__OSI_PRES);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.server_exit_offset);
}

TEST(get_next_tpkt_encap_layer_exit_offset, matched_osi_acse_layer_persists_exit_offset)
{
    uint8_t data[24] = { 0 };

    Cursor cur;
    cur.set("test", data, sizeof(data));

    // the OSI Pres probe reads first and must not match, then the ACSE probe matches an AARQ tag
    ber_mock_push(OSI_ACSE_AARQ, 1, 2);   // consumed by the OSI Pres probe; not a pres tag
    ber_mock_push(OSI_ACSE_AARQ, 1, 2);   // consumed by the OSI ACSE probe; matches

    fake_packet.packet_flags = PKT_FROM_CLIENT;

    TpktEncapLayerType layer = get_next_tpkt_encap_layer(&fake_packet, &cur);

    CHECK(layer == TPKT_ENCAP_LAYER__OSI_ACSE);
    CHECK_EQUAL((unsigned)sizeof(data), fake_flow_data.ssn_data.client_exit_offset);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
