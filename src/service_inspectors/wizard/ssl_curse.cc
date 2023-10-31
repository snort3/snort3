//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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
// ssl_curse.cc author Maya Dagon <mdagon@cisco.com>
// Refactored from curses.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>

#include "ssl_curse.h"
#include "curse_book.h"

namespace SSL_Const
{
static constexpr uint8_t hdr_len = 9;
static constexpr uint8_t sslv2_msb_set = 0x80;
static constexpr uint8_t client_hello = 0x01;
static constexpr uint8_t sslv3_major_ver = 0x03;
static constexpr uint8_t sslv3_max_minor_ver = 0x03;
}

bool CurseBook::ssl_v2_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    SslTracker& ssl = tracker->ssl;

    if ( ssl.state == SSL_STATE__SSL_NOT_FOUND )
        return false;
    else if ( ssl.state == SSL_STATE__SSL_FOUND )
        return true;

    for ( unsigned i = 0; i < len; ++i )
    {
        uint8_t val = data[i];

        switch ( ssl.state )
        {
        case SSL_STATE__BYTE_0_LEN_MSB:
            if ( (val & SSL_Const::sslv2_msb_set) == 0 )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.total_len = (val & (~SSL_Const::sslv2_msb_set)) << 8;
            ssl.state = SSL_STATE__BYTE_1_LEN_LSB;
            break;

        case SSL_STATE__BYTE_1_LEN_LSB:
            ssl.total_len |= val;
            if ( ssl.total_len < SSL_Const::hdr_len )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.total_len -= SSL_Const::hdr_len;
            ssl.state = SSL_STATE__BYTE_2_CLIENT_HELLO;
            break;

        case SSL_STATE__BYTE_2_CLIENT_HELLO:
            if ( val != SSL_Const::client_hello )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.state = SSL_STATE__BYTE_3_MAX_MINOR_VER;
            break;

        case SSL_STATE__BYTE_3_MAX_MINOR_VER:
            if ( val > SSL_Const::sslv3_max_minor_ver )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.state = SSL_STATE__BYTE_4_V3_MAJOR;
            break;

        case SSL_STATE__BYTE_4_V3_MAJOR:
            if ( val > SSL_Const::sslv3_major_ver )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.state = SSL_STATE__BYTE_5_SPECS_LEN_MSB;
            break;

        case SSL_STATE__BYTE_5_SPECS_LEN_MSB:
            ssl.specs_len = val << 8;
            ssl.state = SSL_STATE__BYTE_6_SPECS_LEN_LSB;
            break;

        case SSL_STATE__BYTE_6_SPECS_LEN_LSB:
            ssl.specs_len |= val;

            if ( ssl.total_len < ssl.specs_len )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.total_len -= ssl.specs_len;
            ssl.state = SSL_STATE__BYTE_7_SSNID_LEN_MSB;
            break;

        case SSL_STATE__BYTE_7_SSNID_LEN_MSB:
            ssl.ssnid_len = val << 8;
            ssl.state = SSL_STATE__BYTE_8_SSNID_LEN_LSB;
            break;

        case SSL_STATE__BYTE_8_SSNID_LEN_LSB:
            ssl.ssnid_len |= val;

            if ( ssl.total_len < ssl.ssnid_len )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.total_len -= ssl.ssnid_len;
            ssl.state = SSL_STATE__BYTE_9_CHLNG_LEN_MSB;
            break;

        case SSL_STATE__BYTE_9_CHLNG_LEN_MSB:
            ssl.chlng_len = val << 8;
            ssl.state = SSL_STATE__BYTE_10_CHLNG_LEN_LSB;
            break;

        case SSL_STATE__BYTE_10_CHLNG_LEN_LSB:
            ssl.chlng_len |= val;

            if ( ssl.total_len < ssl.chlng_len )
            {
                ssl.state = SSL_STATE__SSL_NOT_FOUND;

                return false;
            }

            ssl.state = SSL_STATE__SSL_FOUND;

            return true;

        default:
            return false;
        }
    }

    return false;
}

#ifdef CATCH_TEST_BUILD

#include "catch/catch.hpp"
#include <cstring>

// client hello with v2 header advertising sslv2
static const uint8_t ssl_v2_ch[] =
{
    0x80,0x59,0x01,0x00,0x02,0x00,0x30,0x00,0x00,0x00,0x20,0x00,0x00,0x39,0x00,0x00,
    0x38,0x00,0x00,0x35,0x00,0x00,0x16,0x00,0x00,0x13,0x00,0x00,0x0a,0x00,0x00,0x33,
    0x00,0x00,0x32,0x00,0x00,0x2f,0x00,0x00,0x07,0x00,0x00,0x05,0x00,0x00,0x04,0x00,
    0x00,0x15,0x00,0x00,0x12,0x00,0x00,0x09,0x00,0x00,0xff,0xda,0x86,0xfa,0xb4,0x73,
    0x5a,0x1e,0x11,0xd1,0xdb,0x58,0x4b,0x59,0xe1,0x07,0x51,0x5f,0x13,0x46,0xa2,0xdd,
    0xee,0xda,0xc1,0x9d,0xdc,0xd7,0xb8,0x86,0x51,0x10,0x5a
};

// client hello with v2 header advertising tls 1.0
static const uint8_t ssl_v2_v3_ch[] =
{
    0x80,0x59,0x01,0x03,0x01,0x00,0x30,0x00,0x00,0x00,0x20,0x00,0x00,0x39,0x00,0x00,
    0x38,0x00,0x00,0x35,0x00,0x00,0x16,0x00,0x00,0x13,0x00,0x00,0x0a,0x00,0x00,0x33,
    0x00,0x00,0x32,0x00,0x00,0x2f,0x00,0x00,0x07,0x00,0x00,0x05,0x00,0x00,0x04,0x00,
    0x00,0x15,0x00,0x00,0x12,0x00,0x00,0x09,0x00,0x00,0xff,0xda,0x86,0xfa,0xb4,0x73,
    0x5a,0x1e,0x11,0xd1,0xdb,0x58,0x4b,0x59,0xe1,0x07,0x51,0x5f,0x13,0x46,0xa2,0xdd,
    0xee,0xda,0xc1,0x9d,0xdc,0xd7,0xb8,0x86,0x51,0x10,0x5a
};

TEST_CASE("sslv2 detect", "[SslV2Curse]")
{
    uint32_t max_detect = static_cast<uint32_t>(SSL_STATE__BYTE_10_CHLNG_LEN_LSB);
    CurseTracker tracker{ };

    auto test = [&](uint32_t incr_by,const uint8_t* ch)
        {
            uint32_t i = 0;
            while ( i <= max_detect )
            {
                if ( (i + incr_by - 1) < max_detect )
                {
                    CHECK(tracker.ssl.state == static_cast<SSL_State>(i));
                    CHECK(false == CurseBook::ssl_v2_curse(&ch[i],sizeof(uint8_t) * incr_by,&tracker));
                }
                else
                {
                    CHECK(true == CurseBook::ssl_v2_curse(&ch[i],sizeof(uint8_t) * incr_by,&tracker));
                    CHECK(SSL_STATE__SSL_FOUND == tracker.ssl.state);
                }

                i += incr_by;
            }
            // subsequent checks must return found
            CHECK(true == CurseBook::ssl_v2_curse(&ch[max_detect + 1],sizeof(uint8_t),&tracker));
            CHECK(SSL_STATE__SSL_FOUND == tracker.ssl.state);
        };

    // sslv2 with ssl version 2
    SECTION("1 byte v2"){ test(1,ssl_v2_ch); }
    SECTION("2 bytes v2"){ test(2,ssl_v2_ch); }
    SECTION("3 bytes v2"){ test(3,ssl_v2_ch); }
    SECTION("4 bytes v2"){ test(4,ssl_v2_ch); }
    SECTION("5 bytes v2"){ test(5,ssl_v2_ch); }
    SECTION("6 bytes v2"){ test(6,ssl_v2_ch); }
    SECTION("7 bytes v2"){ test(7,ssl_v2_ch); }
    SECTION("8 bytes v2"){ test(8,ssl_v2_ch); }
    SECTION("9 bytes v2"){ test(9,ssl_v2_ch); }
    SECTION("10 bytes v2"){ test(10,ssl_v2_ch); }
    SECTION("11 bytes v2"){ test(11,ssl_v2_ch);}

    // sslv2 with tls version 1.0
    SECTION("1 byte v2_v3"){ test(1,ssl_v2_v3_ch); }
    SECTION("2 bytes v2_v3"){ test(2,ssl_v2_v3_ch); }
    SECTION("3 bytes v2_v3"){ test(3,ssl_v2_v3_ch); }
    SECTION("4 bytes v2_v3"){ test(4,ssl_v2_v3_ch); }
    SECTION("5 bytes v2_v3"){ test(5,ssl_v2_v3_ch); }
    SECTION("6 bytes v2_v3"){ test(6,ssl_v2_v3_ch); }
    SECTION("7 bytes v2_v3"){ test(7,ssl_v2_v3_ch); }
    SECTION("8 bytes v2_v3"){ test(8,ssl_v2_v3_ch); }
    SECTION("9 bytes v2_v3"){ test(9,ssl_v2_v3_ch); }
    SECTION("10 bytes v2_v3"){ test(10,ssl_v2_v3_ch); }
    SECTION("11 bytes v2_v3"){ test(11,ssl_v2_v3_ch); }
}

TEST_CASE("sslv2 not found", "[SslV2Curse]")
{
    uint32_t max_detect = static_cast<uint32_t>(SSL_STATE__BYTE_10_CHLNG_LEN_LSB);
    CurseTracker tracker{};
    uint8_t bad_data[] = {0x00,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    auto test = [&](uint32_t fail_at_byte)
        {
            uint8_t ch_data[sizeof(ssl_v2_ch)];
            memcpy(ch_data,ssl_v2_ch,sizeof(ssl_v2_ch));

            ch_data[fail_at_byte] = bad_data[fail_at_byte];

            for ( uint32_t i = 0; i <= fail_at_byte; i++ )
            {
                if ( i < fail_at_byte )
                {
                    CHECK(tracker.ssl.state == static_cast<SSL_State>(i));
                    CHECK(false == CurseBook::ssl_v2_curse(&ch_data[i],sizeof(uint8_t),&tracker));
                }
                else
                {
                    CHECK(false == CurseBook::ssl_v2_curse(&ch_data[i],sizeof(uint8_t),&tracker));
                    CHECK(SSL_STATE__SSL_NOT_FOUND == tracker.ssl.state);
                }
            }
            // subsequent checks must return ssl not found
            CHECK(false == CurseBook::ssl_v2_curse(&ch_data[max_detect + 1],sizeof(uint8_t),&tracker));
            CHECK(SSL_STATE__SSL_NOT_FOUND == tracker.ssl.state);
        };

    SECTION("byte 0"){ test(0);}
    SECTION("byte 1"){ test(1);}
    SECTION("byte 2"){ test(2);}
    SECTION("byte 3"){ test(3);}
    SECTION("byte 4"){ test(4);}
    SECTION("byte 6"){ test(6);}
    SECTION("byte 8"){ test(8);}
    SECTION("byte 10"){ test(10);}
}

#endif
