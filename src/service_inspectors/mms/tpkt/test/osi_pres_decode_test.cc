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

// osi_pres_decode_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../osi_pres_decode.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// header-only BerReader so we don't have to link the production helpers/ber.cc
#include "ber_mock.h"

using namespace snort;

uint32_t get_max_loops(const Cursor*const)
{ return 0xFFFF; }

uint32_t get_max_pos(const Cursor*, uint32_t idx, uint32_t length)
{ return idx + length; }

uint32_t get_tpkt_work_budget()
{ return 0xFFFF; }

uint16_t mock_charge_calls = 0;
void charge_tpkt_work_budget()
{ mock_charge_calls++; }

TpktAppliSearchStateType tpkt_search_from_osi_acse_layer(Cursor*)
{ return TPKT_APPLI_SEARCH_STATE__EXIT; }

namespace snort
{
Packet* DetectionEngine::get_current_packet()
{ return nullptr; }

FlowData* FlowDataStore::get(unsigned) const
{ return nullptr; }
}
unsigned TpktFlowData::inspector_id = 0;


TEST_GROUP(osi_pres_decode_test)
{
    void setup() override
    { 
        mock_charge_calls = 0;
        ber_mock_reset();
    }

    void teardown() override
    { ber_mock_reset(); }
};

TEST(osi_pres_decode_test, decode_osi_pres_context_list_item_unknown_type)
{
    ber_mock_push(0x30, 4);
    ber_mock_push(0x77, 1);

    uint8_t data[6] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_context_list_item(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL((unsigned)sizeof(data), cur.get_pos());
    CHECK_EQUAL(1, mock_charge_calls);
}

TEST(osi_pres_decode_test, decode_osi_pres_normal_mode_params_inner_charge_definition_list)
{
    ber_mock_push(0x00, 100);   // normal-mode params container
    ber_mock_push(0xA4, 100);   // OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_LIST
    ber_mock_push(0x00, 0, 2, false);

    uint8_t data[16] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_normal_mode_params(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    // one charge for the outer normal-mode loop, one for the inner
    CHECK_EQUAL(2, mock_charge_calls);
}

TEST(osi_pres_decode_test, decode_osi_pres_normal_mode_params_inner_charge_definition_result_list)
{
    ber_mock_push(0x00, 100);   // normal-mode params container
    ber_mock_push(0xA5, 100);   // OSI_PRES_NORMAL_PARAM_PRES_CONTEXT_DEFINITION_RESULT_LIST
    ber_mock_push(0x00, 0, 2, false);

    uint8_t data[16] = { 0 };
    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_normal_mode_params(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    // one charge for the outer normal-mode loop, one for the inner
    CHECK_EQUAL(2, mock_charge_calls);
}

TEST(osi_pres_decode_test, resolve_mode_selector_zero_length_mode_value)
{
    uint8_t data[7] = { 0 };
    data[6] = OSI_PRES_MODE__NORMAL;

    ber_mock_push(0x31, 4);                       // OSI_PRES_TYPE_SEQ
    ber_mock_push(0xA0, 2);                       // OSI_PRES_MODE_SELECTOR_SEQ
    ber_mock_push(0x80, 0, 2, true, data + 6);    // OSI_PRES_MODE_VALUE, no value octet

    Cursor cur;
    cur.set("test", data, 6);

    BerReader ber(cur);

    OsiPresPpduModeSelectorType res = resolve_mode_selector(&ber, &cur, OSI_SESSION_SPDU__CN);

    CHECK(res == OSI_PRES_MODE__INVALID);
    CHECK_EQUAL(6u, cur.get_pos());
}

TEST(osi_pres_decode_test, resolve_mode_selector_normal_mode_value_in_bounds)
{
    uint8_t data[8] = { 0 };
    data[6] = OSI_PRES_MODE__NORMAL;

    ber_mock_push(0x31, 4);                       // OSI_PRES_TYPE_SEQ
    ber_mock_push(0xA0, 2);                       // OSI_PRES_MODE_SELECTOR_SEQ
    ber_mock_push(0x80, 1, 2, true, data + 6);    // OSI_PRES_MODE_VALUE

    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    OsiPresPpduModeSelectorType res = resolve_mode_selector(&ber, &cur, OSI_SESSION_SPDU__AC);

    CHECK(res == OSI_PRES_MODE__NORMAL);
    CHECK_EQUAL(7u, cur.get_pos());
}

TEST(osi_pres_decode_test, resolve_mode_selector_oversized_mode_value_length)
{
    uint8_t data[11] = { 0x31, 0x08, 0xA0, 0x06, 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xFF };
    data[10] = OSI_PRES_MODE__NORMAL;

    ber_mock_push(0x31, 8);                                // OSI_PRES_TYPE_SEQ
    ber_mock_push(0xA0, 6);                                // OSI_PRES_MODE_SELECTOR_SEQ
    ber_mock_push(0x80, 0xFFFFFFFF, 6, true, data + 10);   // OSI_PRES_MODE_VALUE

    Cursor cur;
    cur.set("test", data, 10);

    BerReader ber(cur);

    OsiPresPpduModeSelectorType res = resolve_mode_selector(&ber, &cur, OSI_SESSION_SPDU__CN);

    CHECK(res == OSI_PRES_MODE__INVALID);
    CHECK_EQUAL(10u, cur.get_pos());
}

TEST(osi_pres_decode_test, resolve_mode_selector_truncated_mode_value)
{
    uint8_t data[8] = { 0 };
    data[6] = OSI_PRES_MODE__NORMAL;

    ber_mock_push(0x31, 4);                       // OSI_PRES_TYPE_SEQ
    ber_mock_push(0xA0, 2);                       // OSI_PRES_MODE_SELECTOR_SEQ
    ber_mock_push(0x80, 2, 2, true, data + 6);    // OSI_PRES_MODE_VALUE, one octet short

    Cursor cur;
    cur.set("test", data, 7);

    BerReader ber(cur);

    OsiPresPpduModeSelectorType res = resolve_mode_selector(&ber, &cur, OSI_SESSION_SPDU__CN);

    CHECK(res == OSI_PRES_MODE__INVALID);
    CHECK_EQUAL(7u, cur.get_pos());
}

TEST(osi_pres_decode_test, resolve_mode_selector_mode_value_ends_at_buffer_end)
{
    uint8_t data[7] = { 0 };
    data[6] = OSI_PRES_MODE__NORMAL;

    ber_mock_push(0x31, 4);                       // OSI_PRES_TYPE_SEQ
    ber_mock_push(0xA0, 2);                       // OSI_PRES_MODE_SELECTOR_SEQ
    ber_mock_push(0x80, 1, 2, true, data + 6);    // OSI_PRES_MODE_VALUE

    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    OsiPresPpduModeSelectorType res = resolve_mode_selector(&ber, &cur, OSI_SESSION_SPDU__AC);

    CHECK(res == OSI_PRES_MODE__NORMAL);
    CHECK_EQUAL(7u, cur.get_pos());
}

TEST(osi_pres_decode_test, decode_osi_pres_context_list_item_oversized_context_id_length)
{
    uint8_t data[5] = { 0 };
    data[4] = OSI_PRES_CONTEXT_ID__ACSE;

    ber_mock_push(0x30, 8);                                // context list item
    ber_mock_push(0x02, 0xFFFFFFFF, 2, true, data + 4);    // context id

    Cursor cur;
    cur.set("test", data, 4);

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_context_list_item(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL(2u, cur.get_pos());
    CHECK_EQUAL(1, mock_charge_calls);
}

TEST(osi_pres_decode_test, decode_osi_pres_context_list_item_zero_length_context_id)
{
    uint8_t data[5] = { 0 };
    data[4] = OSI_PRES_CONTEXT_ID__ACSE;

    ber_mock_push(0x30, 4);                       // context list item
    ber_mock_push(0x02, 0, 2, true, data + 4);    // context id, no value octet

    Cursor cur;
    cur.set("test", data, 4);

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_context_list_item(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL(4u, cur.get_pos());
    CHECK_EQUAL(1, mock_charge_calls);
}

TEST(osi_pres_decode_test, decode_osi_pres_context_list_item_truncated_context_id)
{
    uint8_t data[5] = { 0 };
    data[4] = OSI_PRES_CONTEXT_ID__ACSE;

    ber_mock_push(0x30, 8);                       // context list item
    ber_mock_push(0x02, 1, 2, true, data + 4);    // context id

    Cursor cur;
    cur.set("test", data, 4);

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_context_list_item(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__EXIT);
    CHECK_EQUAL(4u, cur.get_pos());
    CHECK_EQUAL(1, mock_charge_calls);
}

TEST(osi_pres_decode_test, decode_osi_pres_context_list_item_context_id_in_bounds)
{
    uint8_t data[8] = { 0 };
    data[4] = OSI_PRES_CONTEXT_ID__MMS;

    ber_mock_push(0x30, 6);                       // context list item
    ber_mock_push(0x02, 1, 2, true, data + 4);    // context id
    ber_mock_push(0xA0, 2);                       // OSI_PRES_CONTEXT_LIST_PRES_DATA_VALUES
    ber_mock_push(0xA0, 2);                       // OSI_PRES_SINGLE_ASN1_TYPE
    ber_mock_push(0x30, 1);                       // mms payload

    Cursor cur;
    cur.set("test", data, sizeof(data));

    BerReader ber(cur);

    TpktAppliSearchStateType res = decode_osi_pres_context_list_item(&ber, &cur);

    CHECK(res == TPKT_APPLI_SEARCH_STATE__MMS_FOUND);
    CHECK_EQUAL(2, mock_charge_calls);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
