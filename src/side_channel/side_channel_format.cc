//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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

// side_channel_format.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel_format.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace snort;

std::string sc_msg_hdr_to_text(const SCMsgHdr* sc_hdr)
{
    if ( !sc_hdr )
        return std::string();

    std::stringstream ss;

    ss << sc_hdr->port << ':' << sc_hdr->time_seconds << '.' << sc_hdr->time_u_seconds;

    if ( !ss.good() )
        return std::string();

    return ss.str();
}

std::string sc_msg_data_to_text(const uint8_t* data, uint32_t length)
{
    if ( !data or length == 0 )
        return std::string();

    std::stringstream ss;

    const uint8_t* data_ptr = data;

    for ( uint32_t i = 0; i < length; i++ )
        ss << ',' << std::setfill('0') << std::setw(2) << std::hex << std::uppercase
            << static_cast<int>(*data_ptr++);

    if ( !ss.good() )
        return std::string();

    return ss.str();
}

ConnectorMsg from_text(const char* str_ptr, uint32_t size)
{
    if ( !str_ptr or size == 0 )
        return ConnectorMsg();

    const char* txt_data_ptr = (const char*)memchr(str_ptr, ',', size);

    if ( !txt_data_ptr )
        return ConnectorMsg();

    uint32_t hdr_len = (uint32_t)(txt_data_ptr - str_ptr);

    if ( hdr_len < sizeof("1:1.1") - 1 )
        return ConnectorMsg();

    // sscanf needs a terminated string and the connector buffer is not one
    char hdr_txt[sizeof("65535:18446744073709551615.4294967295")];

    if ( hdr_len >= sizeof(hdr_txt) )
        return ConnectorMsg();

    memcpy(hdr_txt, str_ptr, hdr_len);
    hdr_txt[hdr_len] = '\0';

    uint16_t port;
    uint64_t time_seconds;
    uint32_t time_u_seconds;

    if ( sscanf(hdr_txt, "%hu:%" SCNu64 ".%" SCNu32, &port, &time_seconds, &time_u_seconds) != 3 )
        return ConnectorMsg();

    // a separator plus one hex digit is the least an encoded byte can cost
    const uint32_t data_capacity = (size - hdr_len) / 2;

    uint8_t* new_data = new uint8_t[sizeof(SCMsgHdr) + data_capacity]();
    SCMsgHdr sc_hdr;

    sc_hdr.port = port;
    sc_hdr.time_seconds = time_seconds;
    sc_hdr.time_u_seconds = time_u_seconds;
    sc_hdr.sequence = 0;
    memcpy(new_data, &sc_hdr, sizeof(sc_hdr));

    uint32_t data_pos = sizeof(SCMsgHdr);
    const char* txt_data_end = str_ptr + size;

    while ( txt_data_ptr < txt_data_end )
    {
        char unit[TXT_UNIT_LEN] = { };   // two hex digits and a terminator
        unsigned digits = 0;

        txt_data_ptr += 1;   // step to the character after the comma

        while ( digits < sizeof(unit) - 1 and txt_data_ptr < txt_data_end and
            isxdigit((unsigned char)*txt_data_ptr) )
            unit[digits++] = *txt_data_ptr++;

        if ( digits == 0 or data_pos == sizeof(SCMsgHdr) + data_capacity or
            (txt_data_ptr < txt_data_end and *txt_data_ptr != ',') )
        {
            delete[] new_data;
            return ConnectorMsg();
        }

        new_data[data_pos++] = (uint8_t)strtoul(unit, nullptr, 16);

        txt_data_ptr = (const char*)memchr(txt_data_ptr, ',', txt_data_end - txt_data_ptr);

        if ( !txt_data_ptr )
            break;
    }

    if ( data_pos <= sizeof(SCMsgHdr) )
    {
        delete[] new_data;
        return ConnectorMsg();
    }

    return ConnectorMsg(new_data, data_pos, true);
}


//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST
#include "catch/snort_catch.h"

#define CHECK_CMSG(cmsg, expected_hdr, expected_msg)                                                    \
    do                                                                                                  \
    {                                                                                                   \
        REQUIRE(cmsg.get_data());                                                                       \
        REQUIRE(cmsg.get_length() == sizeof(expected_hdr) + sizeof(expected_msg));                      \
        CHECK(memcmp(cmsg.get_data(), &expected_hdr, sizeof(expected_hdr)) == 0);                       \
        CHECK(memcmp(cmsg.get_data() + sizeof(expected_hdr), expected_msg, sizeof(expected_msg)) == 0); \
    } while ( false )

#define CHECK_NO_CMSG(cmsg)                                                                             \
    do                                                                                                  \
    {                                                                                                   \
        REQUIRE(cmsg.get_data() == nullptr);                                                            \
        REQUIRE(cmsg.get_length() == 0);                                                                \
    } while ( false )

TEST_CASE("hdr_to_text", "[side_channel]")
{
    SECTION("basic")
    {
        SCMsgHdr data = {1, 2, 3, 4};
        std::string expected_txt("1:4.3");

        std::string txt = sc_msg_hdr_to_text(&data);

        CHECK(txt.size() == expected_txt.size());
        CHECK(txt == expected_txt);
    }
    SECTION("max_values")
    {
        SCMsgHdr data = {UINT16_MAX, UINT16_MAX, UINT32_MAX, UINT64_MAX};
        std::string expected_txt("65535:18446744073709551615.4294967295");

        std::string txt = sc_msg_hdr_to_text(&data);

        CHECK(txt.size() == expected_txt.size());
        CHECK(txt == expected_txt);
    }
    SECTION("zeroes")
    {
        SCMsgHdr data = {0, 0, 0, 0};
        std::string expected_txt("0:0.0");

        std::string txt = sc_msg_hdr_to_text(&data);

        CHECK(txt.size() == expected_txt.size());
        CHECK(txt == expected_txt);
    }
}

TEST_CASE("content_to_text", "[side_channel]")
{
    SECTION("basic")
    {
        uint8_t data_len = 6;
        uint8_t* data = new uint8_t[data_len]{0x00, 0x01, 0x0a, 0xab, 0xbb, 0xff};

        std::string expected_txt(",00,01,0A,AB,BB,FF");

        std::string txt = sc_msg_data_to_text(data, data_len);

        CHECK(txt.size() == expected_txt.size());
        CHECK(txt == expected_txt);

        delete[] data;
    }
    SECTION("single_value")
    {
        uint8_t data_len = 1;
        uint8_t* data = new uint8_t[data_len]{0x00};

        std::string expected_txt(",00");

        std::string txt = sc_msg_data_to_text(data, data_len);

        CHECK(txt.size() == expected_txt.size());
        CHECK(txt == expected_txt);

        delete[] data;
    }
    SECTION("data - nullptr")
    {
        std::string txt = sc_msg_data_to_text(nullptr, 10);

        CHECK(txt.empty());
    }
    SECTION("zero length")
    {
        uint8_t data_len = 1;
        uint8_t* data = new uint8_t[data_len]{0x00};

        std::string txt = sc_msg_data_to_text(data, 0);

        CHECK(txt.empty());

        delete[] data;
    }
}

TEST_CASE("from_text", "[side_channel]")
{
    SECTION("positive")
    {
        SECTION("basic")
        {
            std::string txt_msg("1:2.3,00,01,0A,AB,BB,FF");

            SCMsgHdr expected_hdr = {1, 0, 3, 2};
            uint8_t expected_data[] = {0x00, 0x01, 0x0a, 0xab, 0xbb, 0xff};

            ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
        SECTION("single_char_msg")
        {
            std::string txt_msg("1:2.3,00");

            SCMsgHdr expected_hdr = {1, 0, 3, 2};
            uint8_t expected_data[] = {0x00};

            ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
        SECTION("header_zero")
        {
            std::string txt_msg("0:0.0,00");

            SCMsgHdr expected_hdr = {0, 0, 0, 0};
            uint8_t expected_data[] = {0x00};

            ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
        SECTION("hdr_max_values")
        {
            std::string txt_msg("65535:18446744073709551615.4294967295,00");

            SCMsgHdr expected_hdr = {UINT16_MAX, 0, UINT32_MAX, UINT64_MAX};
            uint8_t expected_data[] = {0x00};

            ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
    }
    SECTION("negative")
    {
        SECTION("empty_string")
        {
            const ConnectorMsg cmsg = from_text("", 0);
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("too_short")
        {
            std::string txt_msg("65535");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("invalid_hdr_format")
        {
            std::string txt_msg("11111,00");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("no_msg")
        {
            std::string txt_msg("1:2.3");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("invalid_msg_format")
        {
            std::string txt_msg("1:2.3.foobar");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
    }
    SECTION("bounds")
    {
        // the connectors hand over a buffer sized exactly to the message, so
        // nothing here may be NUL-terminated
        SECTION("single_digit_tokens")
        {
            std::string txt_msg("1:2.3");
            uint8_t expected_data[60];

            for ( unsigned i = 0; i < sizeof(expected_data); i++ )
            {
                txt_msg += ",1";
                expected_data[i] = 0x01;
            }

            SCMsgHdr expected_hdr = {1, 0, 3, 2};

            ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
        SECTION("token_truncated_by_length")
        {
            const char txt_msg[] = "1:2.3,AA,BB";

            SCMsgHdr expected_hdr = {1, 0, 3, 2};
            uint8_t expected_data[] = {0xaa, 0x0b};

            // declare "1:2.3,AA,B" -- the final B is the whole token in range
            ConnectorMsg cmsg = from_text(txt_msg, 10);
            CHECK_CMSG(cmsg, expected_hdr, expected_data);
        }
        SECTION("separator_at_end_of_length")
        {
            const char txt_msg[] = "1:2.3,AA,BB";

            // declare "1:2.3,AA," -- no digit follows the last separator
            const ConnectorMsg cmsg = from_text(txt_msg, 9);
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("over_long_hex_run")
        {
            std::string txt_msg("1:2.3,ABCDEF");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("whitespace_padded_token")
        {
            std::string txt_msg("1:2.3, 41");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
        SECTION("header_longer_than_any_valid_one")
        {
            std::string txt_msg("65535:18446744073709551615.42949672950,00");

            const ConnectorMsg cmsg = from_text(txt_msg.c_str(), txt_msg.size());
            CHECK_NO_CMSG(cmsg);
        }
    }
}

#endif
