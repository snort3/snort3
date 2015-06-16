//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "value.h"

#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>

#include "sfip/sfip_t.h"
#include "sfip/sf_ip.h"

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

void Value::get_addr(sfip_t& addr) const
{
    if ( str.size() == 4 )
        sfip_set_raw(&addr, str.c_str(), AF_INET);

    else if ( str.size() == 16 )
        sfip_set_raw(&addr, str.c_str(), AF_INET6);

    else
        memset(&addr, 0, sizeof(addr));
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

