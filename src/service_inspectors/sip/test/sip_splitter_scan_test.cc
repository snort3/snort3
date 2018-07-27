//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
//sip_splitter_scan_test.cc author Pratik Shinde <pshinde2@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_splitter_test.h"

#include "log/messages.h"
#include "service_inspectors/sip/sip_splitter.h"
#include "stream/stream_splitter.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(sip_splitter_scan_test)
{
    SipSplitterUT ssut = SipSplitterUT(SipSplitter(true));

    void setup()
    {
        ssut.splitter_reset_states();
    }
};

TEST(sip_splitter_scan_test, scan_start_content_len_test)
{
    uint32_t fp = 0;
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"0xBEEF0xBEEF\n", 13, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_CONTENT_LEN_CMD);
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_start_content_len_negative_test)
{
    uint32_t fp = 0;
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"0xBEEF0xBEEF", 12, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_START_STATE);
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_process_cmd_test)
{
    uint32_t fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_CONTENT_LEN_CMD);
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"C", 1, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_CONTENT_LEN_CMD);
    CHECK_EQUAL(*ssut.splitter_get_next_letter(), (ssut.splitter_get_content_length_key())[1]);
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_content_len_convert_body_search_test)
{
    uint32_t fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_CONTENT_LEN_CONVERT);
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"144 ", 4, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_BODY_SEARCH);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 144);
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_content_len_invalid_test)
{
    uint32_t fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_CONTENT_LEN_CONVERT);
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"144i", 4, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_TRUE(ssut.is_init());
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_search_body_test)
{
    uint32_t fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_BODY_SEARCH);
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"\r\n\r\n", 4, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_FLUSH_STATE);
    CHECK_EQUAL(fp, 0);
    
    ssut.splitter_reset_states();

    ssut.splitter_set_paf_state(SIP_PAF_BODY_SEARCH);
    ret = ssut.splitter_scan(nullptr, (const uint8_t *)"\n\n", 2, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_FLUSH_STATE);
    CHECK_EQUAL(fp, 0);
}

TEST(sip_splitter_scan_test, scan_flush_test)
{
    uint32_t fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_FLUSH_STATE);
    ssut.splitter_set_content_length(6);

    // Sip splitter starts searching body from one character behind the actual body.
    snort::StreamSplitter::Status ret = ssut.splitter_scan(nullptr,
                                        (const uint8_t *)"\nfoobar", 7, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::FLUSH);
    CHECK_TRUE(ssut.is_init());
    CHECK_EQUAL(fp, 7);
    
    ssut.splitter_reset_states();
    // Whole Sip body is not in one buffer
    fp = 0;
    ssut.splitter_set_paf_state(SIP_PAF_FLUSH_STATE);
    ssut.splitter_set_content_length(12);

    ret = ssut.splitter_scan(nullptr, (const uint8_t *)"\nfoobar", 7, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::SEARCH);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_FLUSH_STATE);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 5);
    CHECK_EQUAL(fp, 0);

    //Continue scanning the remaining buffer
    ret = ssut.splitter_scan(nullptr, (const uint8_t *)"foobar", 6, 0, &fp);
    CHECK_EQUAL(ret, snort::StreamSplitter::FLUSH);
    CHECK_TRUE(ssut.is_init());
    CHECK_EQUAL(fp, 6);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
