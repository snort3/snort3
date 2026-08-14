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

// file_mime_log_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../file_mime_log.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

static uint8_t* const PTR_UNSET = (uint8_t*)-10;
static const uint32_t LEN_UNSET = -11;

TEST_GROUP(mail_log_basic)
{
    uint8_t* filename;
    uint32_t filename_len;
    uint8_t* headers;
    uint32_t headers_len;
    uint8_t* senders;
    uint32_t senders_len;
    uint8_t* recipients;
    uint32_t recipients_len;

    void setup() override
    {
        filename = PTR_UNSET;
        filename_len = LEN_UNSET;
        headers = PTR_UNSET;
        headers_len = LEN_UNSET;
        senders = PTR_UNSET;
        senders_len = LEN_UNSET;
        recipients = PTR_UNSET;
        recipients_len = LEN_UNSET;
    }
};

TEST(mail_log_basic, empty_no_logging)
{
    snort::MailLogState state(nullptr);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);
}

TEST(mail_log_basic, empty_with_logging)
{
    snort::MailLogConfig config{true, true, true, true, 0};
    snort::MailLogState state(&config);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(nullptr != filename);
    CHECK(0 == filename_len);
    CHECK(nullptr != headers);
    CHECK(0 == headers_len);
    CHECK(nullptr != senders);
    CHECK(0 == senders_len);
    CHECK(nullptr != recipients);
    CHECK(0 == recipients_len);
}

TEST(mail_log_basic, no_logging)
{
    snort::MailLogConfig config;
    snort::MailLogState state(&config);

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);

    const char* data1 = "1";
    int res1 = state.log_file_name((const uint8_t*)data1, 1);

    const char* data2 = "2";
    int res2 = state.log_email_hdrs((const uint8_t*)data2, 1);

    const char* data3 = ":3";
    int res3 = state.log_email_id((const uint8_t*)data3, 2, snort::EMAIL_SENDER);

    const char* data4 = ":4";
    int res4 = state.log_email_id((const uint8_t*)data4, 2, snort::EMAIL_RECIPIENT);

    CHECK(-1 == res1);
    CHECK(-1 == res2);
    CHECK(-1 == res3);
    CHECK(-1 == res4);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);
}

TEST(mail_log_basic, name_logging)
{
    snort::MailLogConfig config;
    config.log_filename = true;
    snort::MailLogState state(&config);

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr != filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);

    const char* data1 = "1";
    int res1 = state.log_file_name((const uint8_t*)data1, 1);

    const char* data2 = "2";
    int res2 = state.log_email_hdrs((const uint8_t*)data2, 1);

    const char* data3 = ":3";
    int res3 = state.log_email_id((const uint8_t*)data3, 2, snort::EMAIL_SENDER);

    const char* data4 = ":4";
    int res4 = state.log_email_id((const uint8_t*)data4, 2, snort::EMAIL_RECIPIENT);

    CHECK(0 == res1);
    CHECK(-1 == res2);
    CHECK(-1 == res3);
    CHECK(-1 == res4);

    CHECK(true == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(1 == filename_len);
    CHECK(0 == headers_len);
    CHECK(0 == senders_len);
    CHECK(0 == recipients_len);

    CHECK(nullptr != filename);
    CHECK(nullptr == headers);
    CHECK(nullptr == senders);
    CHECK(nullptr == recipients);

    CHECK('1' == filename[0]);
}

TEST(mail_log_basic, header_logging)
{
    snort::MailLogConfig config;
    config.log_email_hdrs = true;
    config.email_hdrs_log_depth = 64;
    snort::MailLogState state(&config);

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr != headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);

    const char* data1 = "1";
    int res1 = state.log_file_name((const uint8_t*)data1, 1);

    const char* data2 = "2";
    int res2 = state.log_email_hdrs((const uint8_t*)data2, 1);

    const char* data3 = ":3";
    int res3 = state.log_email_id((const uint8_t*)data3, 2, snort::EMAIL_SENDER);

    const char* data4 = ":4";
    int res4 = state.log_email_id((const uint8_t*)data4, 2, snort::EMAIL_RECIPIENT);

    CHECK(-1 == res1);
    CHECK(0 == res2);
    CHECK(-1 == res3);
    CHECK(-1 == res4);

    CHECK(false == state.is_file_name_present());
    CHECK(true == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == filename_len);
    CHECK(1 == headers_len);
    CHECK(0 == senders_len);
    CHECK(0 == recipients_len);

    CHECK(nullptr == filename);
    CHECK(nullptr != headers);
    CHECK(nullptr == senders);
    CHECK(nullptr == recipients);

    CHECK('2' == headers[0]);
}

TEST(mail_log_basic, sender_logging)
{
    snort::MailLogConfig config;
    config.log_mailfrom = true;
    snort::MailLogState state(&config);

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr != senders);
    CHECK(0 == senders_len);
    CHECK(nullptr == recipients);
    CHECK(0 == recipients_len);

    const char* data1 = "1";
    int res1 = state.log_file_name((const uint8_t*)data1, 1);

    const char* data2 = "2";
    int res2 = state.log_email_hdrs((const uint8_t*)data2, 1);

    const char* data3 = ":3";
    int res3 = state.log_email_id((const uint8_t*)data3, 2, snort::EMAIL_SENDER);

    const char* data4 = ":4";
    int res4 = state.log_email_id((const uint8_t*)data4, 2, snort::EMAIL_RECIPIENT);

    CHECK(-1 == res1);
    CHECK(-1 == res2);
    CHECK(0 == res3);
    CHECK(-1 == res4);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(true == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == filename_len);
    CHECK(0 == headers_len);
    CHECK(1 == senders_len);
    CHECK(0 == recipients_len);

    CHECK(nullptr == filename);
    CHECK(nullptr == headers);
    CHECK(nullptr != senders);
    CHECK(nullptr == recipients);

    CHECK('3' == senders[0]);
}

TEST(mail_log_basic, recipient_logging)
{
    snort::MailLogConfig config;
    config.log_rcptto = true;
    snort::MailLogState state(&config);

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(false == state.is_email_to_present());
    CHECK(nullptr == filename);
    CHECK(0 == filename_len);
    CHECK(nullptr == headers);
    CHECK(0 == headers_len);
    CHECK(nullptr == senders);
    CHECK(0 == senders_len);
    CHECK(nullptr != recipients);
    CHECK(0 == recipients_len);

    const char* data1 = "1";
    int res1 = state.log_file_name((const uint8_t*)data1, 1);

    const char* data2 = "2";
    int res2 = state.log_email_hdrs((const uint8_t*)data2, 1);

    const char* data3 = ":3";
    int res3 = state.log_email_id((const uint8_t*)data3, 2, snort::EMAIL_SENDER);

    const char* data4 = ":4";
    int res4 = state.log_email_id((const uint8_t*)data4, 2, snort::EMAIL_RECIPIENT);

    CHECK(-1 == res1);
    CHECK(-1 == res2);
    CHECK(-1 == res3);
    CHECK(0 == res4);

    CHECK(false == state.is_file_name_present());
    CHECK(false == state.is_email_hdrs_present());
    CHECK(false == state.is_email_from_present());
    CHECK(true == state.is_email_to_present());

    state.get_file_name(&filename, &filename_len);
    state.get_email_hdrs(&headers, &headers_len);
    state.get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    state.get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == filename_len);
    CHECK(0 == headers_len);
    CHECK(0 == senders_len);
    CHECK(1 == recipients_len);

    CHECK(nullptr == filename);
    CHECK(nullptr == headers);
    CHECK(nullptr == senders);
    CHECK(nullptr != recipients);

    CHECK('4' == recipients[0]);
}

TEST_GROUP(mail_log_limit_preset)
{
    static constexpr int SIZE_LIMIT = 1024; // expected limit for filename, headers, senders and recipients
    snort::MailLogState* state;

    const char* mark1 = " filename mark";
    const char* mark2 = " header mark";
    const char* mark3 = ":sender mark";
    const char* mark4 = ":recipient mark";

    const int mark1_count = 3;
    const int mark2_count = 3;
    const int mark3_count = 3;
    const int mark4_count = 3;

    const char* expected1 = " filename mark, filename mark, filename mark";
    const char* expected2 = " header mark header mark header mark";
    const char* expected3 = "sender mark,sender mark,sender mark";
    const char* expected4 = "recipient mark,recipient mark,recipient mark";

    void setup() override
    {
        snort::MailLogConfig config;

        config.log_mailfrom = true;
        config.log_rcptto = true;
        config.log_filename = true;
        config.log_email_hdrs = true;
        config.email_hdrs_log_depth = SIZE_LIMIT;

        state = new snort::MailLogState(&config);
        fill();
    }

    void teardown() override
    {
        check();
        delete state;
    }

    void fill()
    {
        CHECK(nullptr != state);

        CHECK(false == state->is_file_name_present());
        CHECK(false == state->is_email_hdrs_present());
        CHECK(false == state->is_email_from_present());
        CHECK(false == state->is_email_to_present());

        for (int i = 0; i < mark1_count; ++i)
            state->log_file_name((const uint8_t*)mark1, strlen(mark1));

        for (int i = 0; i < mark2_count; ++i)
            state->log_email_hdrs((const uint8_t*)mark2, strlen(mark2));

        for (int i = 0; i < mark3_count; ++i)
            state->log_email_id((const uint8_t*)mark3, strlen(mark3), snort::EMAIL_SENDER);

        for (int i = 0; i < mark4_count; ++i)
            state->log_email_id((const uint8_t*)mark4, strlen(mark4), snort::EMAIL_RECIPIENT);
    }

    void check()
    {
        CHECK(nullptr != state);

        CHECK(true == state->is_file_name_present());
        CHECK(true == state->is_email_hdrs_present());
        CHECK(true == state->is_email_from_present());
        CHECK(true == state->is_email_to_present());

        uint8_t* filename = PTR_UNSET;
        uint32_t filename_len = LEN_UNSET;
        uint8_t* headers = PTR_UNSET;
        uint32_t headers_len = LEN_UNSET;
        uint8_t* senders = PTR_UNSET;
        uint32_t senders_len = LEN_UNSET;
        uint8_t* recipients = PTR_UNSET;
        uint32_t recipients_len = LEN_UNSET;

        state->get_file_name(&filename, &filename_len);
        state->get_email_hdrs(&headers, &headers_len);
        state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
        state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);

        CHECK(strlen(expected1) <= filename_len);
        CHECK(strlen(expected2) <= headers_len);
        CHECK(strlen(expected3) <= senders_len);
        CHECK(strlen(expected4) <= recipients_len);

        CHECK(nullptr != filename);
        CHECK(nullptr != headers);
        CHECK(nullptr != senders);
        CHECK(nullptr != recipients);

        STRNCMP_EQUAL(expected1, (const char*)filename, strlen(expected1));
        STRNCMP_EQUAL(expected2, (const char*)headers, strlen(expected2));
        STRNCMP_EQUAL(expected3, (const char*)senders, strlen(expected3));
        STRNCMP_EQUAL(expected4, (const char*)recipients, strlen(expected4));
    }
};

TEST(mail_log_limit_preset, name_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for preexisting data, extra comma and null-character
    int data_len = sizeof(data) - strlen(expected1) - 1 - 1;

    int ret = state->log_file_name(data, data_len);
    CHECK(0 == ret);

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    std::string written((const char*)data, data_len);
    std::string expected;
    expected += expected1;
    expected += ",";
    expected += written;

    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, header_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for preexisting data, no comma and null-character
    int data_len = sizeof(data) - strlen(expected2) - 0 - 1;

    int ret = state->log_email_hdrs(data, data_len);
    CHECK(0 == ret);

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    std::string written((const char*)data, data_len);
    std::string expected;
    expected += expected2;
    expected += written;

    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, sender_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for preexisting data, extra comma, null-character and eaten colon
    int data_len = sizeof(data) - strlen(expected3) - 1 - 1 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);
    CHECK(0 == ret);

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    std::string written((const char*)data + 1, data_len - 1);
    std::string expected;
    expected += expected3;
    expected += ",";
    expected += written;

    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, recipient_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for preexisting data, extra comma, null-character and eaten colon
    int data_len = sizeof(data) - strlen(expected4) - 1 - 1 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);
    CHECK(0 == ret);

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    std::string written((const char*)data + 1, data_len - 1);
    std::string expected;
    expected += expected4;
    expected += ",";
    expected += written;

    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, name_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for preexisting data, extra comma and no room for null-character
    int data_len = sizeof(data) - strlen(expected1) - 1 - 0;

    int ret = state->log_file_name(data, data_len);
    CHECK(0 == ret);

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    std::string written((const char*)data, data_len - 1);
    std::string expected;
    expected += expected1;
    expected += ",";
    expected += written;

    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, header_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for preexisting data, no comma and no room for null-character
    int data_len = sizeof(data) - strlen(expected2) - 0 - 0;

    int ret = state->log_email_hdrs(data, data_len);
    CHECK(0 == ret);

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    std::string written((const char*)data, data_len - 1);
    std::string expected;
    expected += expected2;
    expected += written;

    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, sender_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for preexisting data, extra comma, no null-character and eaten colon
    int data_len = sizeof(data) - strlen(expected3) - 1 - 0 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);
    CHECK(0 == ret);

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    std::string written((const char*)data + 1, data_len - 2);
    std::string expected;
    expected += expected3;
    expected += ",";
    expected += written;

    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, recipient_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for preexisting data, extra comma, no null-character and eaten colon
    int data_len = sizeof(data) - strlen(expected4) - 1 - 0 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);
    CHECK(0 == ret);

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    std::string written((const char*)data + 1, data_len - 2);
    std::string expected;
    expected += expected4;
    expected += ",";
    expected += written;

    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, name_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    int data_len = sizeof(data);

    int ret = state->log_file_name(data, data_len);
    CHECK(0 == ret);

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    // see [mail_log_limit_preset.name_fit] for size calculation
    std::string written((const char*)data, SIZE_LIMIT - strlen(expected1) - 1 - 1);
    std::string expected;
    expected += expected1;
    expected += ",";
    expected += written;

    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, header_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    int data_len = sizeof(data);

    int ret = state->log_email_hdrs(data, data_len);
    CHECK(0 == ret);

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    // see [mail_log_limit_preset.header_fit] for size calculation
    std::string written((const char*)data, SIZE_LIMIT - strlen(expected2) - 0 - 1);
    std::string expected;
    expected += expected2;
    expected += written;

    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, sender_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    data[0] = ':';
    int data_len = sizeof(data);

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);
    CHECK(0 == ret);

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    // see [mail_log_limit_preset.sender_fit] for size calculation
    std::string written((const char*)data + 1, SIZE_LIMIT - strlen(expected3) - 1 - 1 + 1 - 1);
    std::string expected;
    expected += expected3;
    expected += ",";
    expected += written;

    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_preset, recipient_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    data[0] = ':';
    int data_len = sizeof(data);

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);
    CHECK(0 == ret);

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    // see [mail_log_limit_preset.recipients_fit] for size calculation
    std::string written((const char*)data + 1, SIZE_LIMIT - strlen(expected4) - 1 - 1 + 1 - 1);
    std::string expected;
    expected += expected4;
    expected += ",";
    expected += written;

    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

TEST_GROUP(mail_log_limit_once)
{
    static constexpr int SIZE_LIMIT = 1024; // expected limit for filename, headers, senders and recipients
    snort::MailLogState* state;

    void setup() override
    {
        snort::MailLogConfig config;

        config.log_mailfrom = true;
        config.log_rcptto = true;
        config.log_filename = true;
        config.log_email_hdrs = true;
        config.email_hdrs_log_depth = SIZE_LIMIT;

        state = new snort::MailLogState(&config);
        CHECK(nullptr != state);
    }

    void teardown() override
    {
        delete state;
    }
};

TEST(mail_log_limit_once, name_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for null-character
    int data_len = sizeof(data) - 1;

    int ret = state->log_file_name(data, data_len);

    CHECK(0 == ret);
    CHECK(true == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    std::string expected((const char*)data, data_len);
    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, header_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // account for null-character
    int data_len = sizeof(data) - 1;

    int ret = state->log_email_hdrs(data, data_len);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(true == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    std::string expected((const char*)data, data_len);
    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, sender_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for null-character and eaten colon
    int data_len = sizeof(data) - 1 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(true == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    std::string expected((const char*)data + 1, data_len - 1);
    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, recipient_fit)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // account for null-character and eaten colon
    int data_len = sizeof(data) - 1 + 1;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(true == state->is_email_to_present());

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    std::string expected((const char*)data + 1, data_len - 1);
    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, name_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // no room for null-character
    int data_len = sizeof(data) - 0;

    int ret = state->log_file_name(data, data_len);

    CHECK(0 == ret);
    CHECK(true == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    std::string expected((const char*)data, data_len - 1);
    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, header_over_1)
{
    uint8_t data[SIZE_LIMIT];
    memset(data, 'a', sizeof(data));

    // no room for null-character
    int data_len = sizeof(data) - 0;

    int ret = state->log_email_hdrs(data, data_len);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(true == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    std::string expected((const char*)data, data_len - 1);
    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, sender_over_1)
{
    // account for eaten colon
    uint8_t data[SIZE_LIMIT + 1];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // no room for null-character
    int data_len = sizeof(data) - 0;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(true == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    std::string expected((const char*)data + 1, data_len - 2);
    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, recipient_over_1)
{
    // account for eaten colon
    uint8_t data[SIZE_LIMIT + 1];
    memset(data, 'a', sizeof(data));
    data[0] = ':';

    // no room for null-character
    int data_len = sizeof(data) - 0;

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(true == state->is_email_to_present());

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    std::string expected((const char*)data + 1, data_len - 2);
    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, name_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    int data_len = sizeof(data);

    int ret = state->log_file_name(data, data_len);

    CHECK(0 == ret);
    CHECK(true == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* filename = PTR_UNSET;
    uint32_t filename_len = LEN_UNSET;

    state->get_file_name(&filename, &filename_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, filename_len);

    std::string expected((const char*)data, SIZE_LIMIT - 1);
    std::string actual((const char*)filename);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, header_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    int data_len = sizeof(data);

    int ret = state->log_email_hdrs(data, data_len);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(true == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* headers = PTR_UNSET;
    uint32_t headers_len = LEN_UNSET;

    state->get_email_hdrs(&headers, &headers_len);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, headers_len);

    std::string expected((const char*)data, SIZE_LIMIT - 1);
    std::string actual((const char*)headers);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, sender_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    data[0] = ':';
    int data_len = sizeof(data);

    int ret = state->log_email_id(data, data_len, snort::EMAIL_SENDER);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(true == state->is_email_from_present());
    CHECK(false == state->is_email_to_present());

    uint8_t* senders = PTR_UNSET;
    uint32_t senders_len = LEN_UNSET;

    state->get_email_id(&senders, &senders_len, snort::EMAIL_SENDER);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, senders_len);

    std::string expected((const char*)data + 1, SIZE_LIMIT - 1);
    std::string actual((const char*)senders);
    CHECK_COMPARE(expected, ==, actual);
}

TEST(mail_log_limit_once, recipient_doubled)
{
    uint8_t data[SIZE_LIMIT * 2];
    memset(data, 'a', sizeof(data));
    data[0] = ':';
    int data_len = sizeof(data);

    int ret = state->log_email_id(data, data_len, snort::EMAIL_RECIPIENT);

    CHECK(0 == ret);
    CHECK(false == state->is_file_name_present());
    CHECK(false == state->is_email_hdrs_present());
    CHECK(false == state->is_email_from_present());
    CHECK(true == state->is_email_to_present());

    uint8_t* recipients = PTR_UNSET;
    uint32_t recipients_len = LEN_UNSET;

    state->get_email_id(&recipients, &recipients_len, snort::EMAIL_RECIPIENT);
    CHECK_COMPARE(SIZE_LIMIT - 1, ==, recipients_len);

    std::string expected((const char*)data + 1, SIZE_LIMIT - 1);
    std::string actual((const char*)recipients);
    CHECK_COMPARE(expected, ==, actual);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
