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
//sip_splitter_body_search_test.cc author Pratik Shinde <pshinde2@cisco.com>

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

TEST_GROUP(sip_splitter_body_search_test)
{
    SipSplitterUT ssut = SipSplitterUT(SipSplitter(true));

    void setup()
    {
        ssut.splitter_reset_states();
    }
};

TEST(sip_splitter_body_search_test, body_state_unknown_flf_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_UNKNOWN);

    bool result = ssut.splitter_find_body(line_feed);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_LF);
}

TEST(sip_splitter_body_search_test, body_state_unknown_fcr_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_UNKNOWN);

    bool result = ssut.splitter_find_body(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_CR);
}

TEST(sip_splitter_body_search_test, body_state_fcr_scr_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_CR);
    bool result = ssut.splitter_find_body(line_feed);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_SECOND_CR);
}

TEST(sip_splitter_body_search_test, body_state_fcr_fcr_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_CR);
    bool result = ssut.splitter_find_body(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_CR);
}

TEST(sip_splitter_body_search_test, body_state_fcr_unknown_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_CR);

    bool result = ssut.splitter_find_body(no_lf_cr);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_UNKNOWN);
}

TEST(sip_splitter_body_search_test, body_state_flf_unknown_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_LF);

    bool result = ssut.splitter_find_body(no_lf_cr);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_UNKNOWN);
}

TEST(sip_splitter_body_search_test, body_state_flf_fcr_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_LF);

    bool result = ssut.splitter_find_body(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_CR);
}

TEST(sip_splitter_body_search_test, body_state_flf_flush_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_FIRST_LF);

    bool result = ssut.splitter_find_body(line_feed);
    CHECK_TRUE(result);
    //state should not change
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_LF);
}

TEST(sip_splitter_body_search_test, body_state_scr_unknown_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_CR);

    bool result = ssut.splitter_find_body(no_lf_cr);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_UNKNOWN);
}

TEST(sip_splitter_body_search_test, body_state_scr_slf_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_CR);

    bool result = ssut.splitter_find_body(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_SECOND_LF);
}

TEST(sip_splitter_body_search_test, body_state_scr_flush_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_CR);

    bool result = ssut.splitter_find_body(line_feed);
    CHECK_TRUE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_SECOND_CR);
}

TEST(sip_splitter_body_search_test, body_state_slf_unknown_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_LF);

    bool result = ssut.splitter_find_body(no_lf_cr);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_UNKNOWN);
}

TEST(sip_splitter_body_search_test, body_state_slf_fcr_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_LF);

    bool result = ssut.splitter_find_body(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_FIRST_CR);
}

TEST(sip_splitter_body_search_test, body_state_slf_flush_test)
{
    ssut.splitter_set_body_state(SIP_PAF_BODY_START_SECOND_LF);

    bool result = ssut.splitter_find_body(line_feed);
    CHECK_TRUE(result);
    CHECK_EQUAL(ssut.splitter_get_body_state(), SIP_PAF_BODY_START_SECOND_LF);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
