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
//sip_splitter_test.cc author Pratik Shinde <pshinde2@cisco.com>


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

TEST_GROUP(sip_splitter_test)
{
    SipSplitterUT ssut = SipSplitterUT(SipSplitter(true));

    void setup()
    {
        ssut.splitter_reset_states();
    }
};

TEST(sip_splitter_test, callispaf)
{
    bool result = ssut.splitter_is_paf();
    CHECK(result)
}

TEST(sip_splitter_test, reset_states_test)
{
    CHECK_TRUE(ssut.is_init());
}

TEST(sip_splitter_test, find_data_end_single_line_test)
{
    //positive input
    bool result = ssut.splitter_data_end_single_line(line_feed);
    CHECK_TRUE(result);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_CONTENT_LEN_CMD);

    ssut.splitter_reset_states();
    result = ssut.splitter_data_end_single_line(carriage_return);
    CHECK_FALSE(result);
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_START_STATE);
}

TEST(sip_splitter_test, get_length_skip_leading_spaces_test)
{
    for(auto ch : spaces)
    {
        SipPafDataLenStatus status = ssut.splitter_get_length(ch);
        CHECK_EQUAL(status, SIP_PAF_LENGTH_CONTINUE);
        CHECK_EQUAL(ssut.splitter_get_content_length(), UNKNOWN_CONTENT_LENGTH);
    }
}

TEST(sip_splitter_test, get_length_invalid_length_test)
{
    //anything other that space and digit is invalid.
    SipPafDataLenStatus status = ssut.splitter_get_length('-');
    CHECK_EQUAL(status, SIP_PAF_LENGTH_INVALID);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 0);
}

TEST(sip_splitter_test, get_length_valid_single_digit_length_test)
{
    SipPafDataLenStatus status = ssut.splitter_get_length('3');
    CHECK_EQUAL(status, SIP_PAF_LENGTH_CONTINUE);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 3);
}

TEST(sip_splitter_test, get_length_valid_multi_digit_length_test)
{
    ssut.splitter_set_content_length(201);
    SipPafDataLenStatus status = ssut.splitter_get_length('3');
    CHECK_EQUAL(status, SIP_PAF_LENGTH_CONTINUE);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 2013);
}

TEST(sip_splitter_test, get_length_overflow_test)
{
    ssut.splitter_set_content_length(UINT32_MAX-1);
    SipPafDataLenStatus status = ssut.splitter_get_length('3');
    CHECK_EQUAL(status, SIP_PAF_LENGTH_INVALID);
    CHECK_EQUAL(ssut.splitter_get_content_length(), 0);
}

TEST(sip_splitter_test, get_length_finish_test)
{   
    for(auto ch : spaces)
    {
        ssut.splitter_set_content_length(201);
        SipPafDataLenStatus status = ssut.splitter_get_length(ch);
        CHECK_EQUAL(status, SIP_PAF_LENGTH_DONE);
        CHECK_EQUAL(ssut.splitter_get_content_length(), 201);
    }
}

TEST(sip_splitter_test, process_command_skip_leading_spaces_test)
{
    for(auto ch : spaces)
    {
        ssut.splitter_process_command(ch);
        CHECK_TRUE(ssut.is_init());        
    }
}

TEST(sip_splitter_test, process_command_set_next_test)
{
    const char *content_len_key = "Content-Length";
    ssut.splitter_process_command('C');
    CHECK_EQUAL(*ssut.splitter_get_next_letter(), (ssut.splitter_get_content_length_key())[1]);

    ssut.splitter_reset_states();
    ssut.splitter_process_command('l');
    CHECK_EQUAL(*ssut.splitter_get_next_letter(), '\0');

        
    ssut.splitter_reset_states();
    for(int i = 0; content_len_key[i] != '\0'; i++) {
        ssut.splitter_process_command(content_len_key[i]);
        CHECK_EQUAL(*ssut.splitter_get_next_letter(), (ssut.splitter_get_content_length_key())[i+1]);
    }
}

TEST(sip_splitter_test, process_command_invalid_input_test)
{
    ssut.splitter_process_command('O');
    CHECK_TRUE(ssut.is_init());        
}

TEST(sip_splitter_test, process_command_len_convert_test)
{
    ssut.splitter_set_next_letter_last();
    ssut.splitter_process_command(':');
    CHECK_EQUAL(ssut.splitter_get_paf_state(), SIP_PAF_CONTENT_LEN_CONVERT);
}

TEST(sip_splitter_test, process_command_skip_blanks_len_convert_test)
{
    ssut.splitter_set_next_letter_last();
    for(auto ch : blanks)
    {
        ssut.splitter_process_command(ch);
        CHECK_FALSE(ssut.is_init()); 
    }
}

TEST(sip_splitter_test, process_command_invalid_blanks_len_convert_test)
{
    ssut.splitter_set_next_letter_last();
    ssut.splitter_process_command('\r');
    CHECK_TRUE(ssut.is_init()); 
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
