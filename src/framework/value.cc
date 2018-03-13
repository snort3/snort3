//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// value.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "value.h"

#include <cassert>

#include "sfip/sf_cidr.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

Value::~Value()
{
    if ( ss )
        delete ss;
}

void Value::get_mac(uint8_t (&mac)[6]) const
{
    if ( str.size() == sizeof(mac) )
        str.copy((char*)mac, sizeof(mac));
    else
        memset(mac, 0, sizeof(mac));
}

uint32_t Value::get_ip4() const
{
    return (uint32_t)num;
}

void Value::get_addr(uint8_t (&addr)[16]) const
{
    if ( str.size() <= sizeof(addr) )
        str.copy((char*)addr, sizeof(addr));
    else
        memset(addr, 0, sizeof(addr));
}

void Value::get_addr_ip4(uint8_t (&addr)[4]) const
{
    if ( str.size() == sizeof(addr) )
        str.copy((char*)addr, sizeof(addr));
    else
        memset(addr, 0, sizeof(addr));
}

void Value::get_addr_ip6(uint8_t (&addr)[16]) const
{
    if ( str.size() == sizeof(addr) )
        str.copy((char*)addr, sizeof(addr));
    else
        memset(addr, 0, sizeof(addr));
}

void Value::get_addr(SfIp& addr) const
{
    if ( str.size() == 4 )
        addr.set(str.c_str(), AF_INET);

    else if ( str.size() == 16 )
        addr.set(str.c_str(), AF_INET6);

    else
        addr.clear();
}

void Value::get_addr(SfCidr& cidr) const
{
    if ( str.size() == 4 )
        cidr.set(str.c_str(), AF_INET);

    else if ( str.size() == 16 )
        cidr.set(str.c_str(), AF_INET6);

    else
        cidr.clear();
}

void Value::get_bits(PortBitSet& list) const
{
    list.reset();
    std::size_t len = str.size();
    assert(len == list.size());

    for ( std::size_t n = 0; n < len; ++n )
    {
        if ( str[n] == '1' )
            list.set(n);
    }
}

void Value::get_bits(VlanBitSet& list) const
{
    list.reset();
    std::size_t len = str.size();
    assert(len == list.size());

    for ( std::size_t n = 0; n < len; ++n )
    {
        if ( str[n] == '1' )
            list.set(n);
    }
}

void Value::get_bits(ByteBitSet& list) const
{
    list.reset();
    std::size_t len = str.size();
    assert(len == list.size());

    for ( std::size_t n = 0; n < len; ++n )
    {
        if ( str[n] == '1' )
            list.set(n);
    }
}

void Value::set_first_token()
{
    if ( ss )
        delete ss;

    ss = new stringstream(str);
}

bool Value::get_next_token(string& tok)
{
    return ss and ( *ss >> tok );
}

bool Value::get_next_csv_token(string& tok)
{
    return ss and std::getline(*ss, tok, ',');
}

bool Value::strtol(long& n) const
{
    const char* s = str.c_str();

    if ( !*s )
        return false;

    char* end = nullptr;

    n = ::strtol(s, &end, 0);

    if ( *end )
        return false;

    return true;
}

bool Value::strtol(long& n, const std::string& tok) const
{
    const char* s = tok.c_str();

    if ( !*s )
        return false;

    char* end = nullptr;

    n = ::strtol(s, &end, 0);

    if ( *end )
        return false;

    return true;
}

const char* Value::get_as_string()
{
    switch ( type )
    {
    case VT_BOOL:
        str = num ? "true" : "false";
        break;
    case VT_NUM:
        ss = new stringstream;
        *ss << num;
        str = ss->str();
        break;
    default:
        break;
    }
    return str.c_str();
}

void Value::update_mask(uint8_t& mask, uint8_t flag, bool invert)
{
    if ( get_bool() xor invert )
        mask |= flag;
    else
        mask &= ~flag;
}

void Value::update_mask(uint16_t& mask, uint16_t flag, bool invert)
{
    if ( get_bool() xor invert )
        mask |= flag;
    else
        mask &= ~flag;
}

void Value::update_mask(uint32_t& mask, uint32_t flag, bool invert)
{
    if ( get_bool() xor invert )
        mask |= flag;
    else
        mask &= ~flag;
}

void Value::update_mask(uint64_t& mask, uint64_t flag, bool invert)
{
    if ( get_bool() xor invert )
        mask |= flag;
    else
        mask &= ~flag;
}



//---------------------
// unit tests:
//---------------------

#ifdef UNIT_TEST

// The test strings used with some of the APIs below that return IP/MAC
// addrs are random character strings and not actual addresses. This is
// fine since there is no IP address specific processing or validation. The
// internal representation of the data is a C string and the purpose was to
// exercise the APIs to ensure things like length checks are done correctly
// and the string value/zero is returned based on the result etc.

TEST_CASE("mac addr negative test", "[Value]")
{
    unsigned int num_chars;
    uint8_t mac[6];
    uint8_t zero[6];

    memset(zero,0,6);
    Value test_val("12345");

    test_val.get_buffer(num_chars);
    REQUIRE((num_chars == 5));

    test_val.get_mac(mac);
    CHECK(memcmp(mac,zero,6)==0);

}

TEST_CASE("get addr test", "[Value]")
{
    unsigned int num_chars;
    uint8_t addr[16];
    uint8_t zero[16];

    memset(zero,0,16);

    SECTION("valid value")
    {
        Value test_val("1234567890123456");
        const uint8_t* test_str = test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 16));

        test_val.get_addr(addr);
        CHECK(memcmp(addr,test_str,16)==0);
    }
    SECTION("invalid value")
    {
        Value test_val("12345678901234567890");
        test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 20));

        test_val.get_addr(addr);
        CHECK(memcmp(addr,zero,16)==0);
    }

 }

TEST_CASE("get addr IPv4 test", "[Value]")
{
    unsigned int num_chars;
    uint8_t addr[4];
    uint8_t zero[4];

    memset(zero,0,4);

    SECTION("valid value")
    {
        Value test_val("1234");
        const uint8_t* test_str = test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 4));

        test_val.get_addr_ip4(addr);
        CHECK(memcmp(addr,test_str,4)==0);
    }
    SECTION("invalid value")
    {
        Value test_val("123456");
        test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 6));

        test_val.get_addr_ip4(addr);
        CHECK(memcmp(addr,zero,4)==0);
    }
}

TEST_CASE("get addr IPv6 test", "[Value]")
{
    unsigned int num_chars;
    uint8_t addr[16];
    uint8_t zero[16];

    memset(zero,0,16);

    SECTION("valid value")
    {
        Value test_val("1234567890123456");
        const uint8_t * test_str = test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 16));

        test_val.get_addr_ip6(addr);
        CHECK(memcmp(addr,test_str,16)==0);
    }
    SECTION("invalid value")
    {
        Value test_val("123456");
        test_val.get_buffer(num_chars);
        REQUIRE((num_chars == 6));

        test_val.get_addr_ip6(addr);
        CHECK(memcmp(addr,zero,16)==0);
    }
}

TEST_CASE("token test", "[Value]")
{
    string test_str;
    const char * str_val;

    Value test_val("123456");
    test_val.set_first_token();
    test_val.set("123456,abcdef");
    test_val.set_first_token();


    CHECK(test_val.get_next_csv_token(test_str));
    str_val = (const char *)test_str.c_str();
    REQUIRE(str_val != nullptr);
    CHECK((strcmp(str_val,"123456")==0));
}

TEST_CASE("get as string", "[Value]")
{
    const char* str_val;
    bool bool_val = true;
    double num_val = 6;

    Value test_val(bool_val);
    str_val = (const char *)test_val.get_as_string();
    REQUIRE(str_val != nullptr);
    CHECK((strcmp(str_val,"true")==0));

    test_val.set(num_val);
    str_val = (const char *)test_val.get_as_string();
    REQUIRE(str_val != nullptr);
    CHECK((strcmp(str_val,"6")==0));
}


TEST_CASE("update mask", "[Value]")
{
    uint8_t mask8;
    uint16_t mask16;
    uint32_t mask32;
    uint64_t mask64;
    uint8_t flag8;
    uint16_t flag16;
    uint32_t flag32;
    uint64_t flag64;
    bool invert;

    flag8 = 0x10;
    flag16 = 0x1000;
    flag32 = 0x10000000;
    flag64 = 0x1000000000000000;

    SECTION("val true")
    {
        Value test_val(true);

        SECTION("invert true")
        {
            invert = true;

            mask8 = 0x11;
            test_val.update_mask(mask8, flag8, invert);
            CHECK(mask8 == 0x01);

            mask16 = 0x1100;
            test_val.update_mask(mask16, flag16, invert);
            CHECK((mask16 == 0x0100));

            mask32 = 0x11000000;
            test_val.update_mask(mask32, flag32, invert);
            CHECK((mask32 == 0x01000000));

            mask64 = 0x1100000000000000;
            test_val.update_mask(mask64, flag64, invert);
            CHECK((mask64 == 0x0100000000000000));
        }

        SECTION("invert false")
        {
            invert = false;
            mask8 = 0x01;
            test_val.update_mask(mask8, flag8, invert);
            CHECK((mask8 == 0x11));

            mask16 = 0x0100;
            test_val.update_mask(mask16, flag16, invert);
            CHECK((mask16 == 0x1100));

            mask32 = 0x01000000;
            test_val.update_mask(mask32, flag32, invert);
            CHECK((mask32 == 0x11000000));

            mask64 = 0x0100000000000000;
            test_val.update_mask(mask64, flag64, invert);
            CHECK((mask64 == 0x1100000000000000));
        }
    }

    SECTION("val false")
    {
        Value test_val(true);

        SECTION("invert false")
        {
            invert = true;

            mask8 = 0x11;
            test_val.update_mask(mask8, flag8, invert);
            CHECK(mask8 == 0x01);

            mask16 = 0x1100;
            test_val.update_mask(mask16, flag16, invert);
            CHECK((mask16 == 0x0100));

            mask32 = 0x11000000;
            test_val.update_mask(mask32, flag32, invert);
            CHECK((mask32 == 0x01000000));

            mask64 = 0x1100000000000000;
            test_val.update_mask(mask64, flag64, invert);
            CHECK((mask64 == 0x0100000000000000));
        }

        SECTION("invert true")
        {
            invert = false;
            mask8 = 0x01;
            test_val.update_mask(mask8, flag8, invert);
            CHECK((mask8 == 0x11));

            mask16 = 0x0100;
            test_val.update_mask(mask16, flag16, invert);
            CHECK((mask16 == 0x1100));

            mask32 = 0x01000000;
            test_val.update_mask(mask32, flag32, invert);
            CHECK((mask32 == 0x11000000));

            mask64 = 0x0100000000000000;
            test_val.update_mask(mask64, flag64, invert);
            CHECK((mask64 == 0x1100000000000000));
        }
    }
}

#endif


