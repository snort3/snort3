/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// value.cc author Russ Combs <rucombs@cisco.com>

#include "value.h"

#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>

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

void Value::get_bits(PortList& list) const
{
    list.reset();
    unsigned len = str.size();
    assert(len == list.size());

    for ( unsigned n = 0; n < len; ++n )
    {
        if ( str[n] == '1' )
            list.set(n);
    }
}

void Value::get_bits(VlanList& list) const
{
    list.reset();
    unsigned len = str.size();
    assert(len == list.size());

    for ( unsigned n = 0; n < len; ++n )
    {   
        if ( str[n] == '1' )
            list.set(n);
    }
}

void Value::get_bits(ByteList& list) const
{
    list.reset();
    unsigned len = str.size();
    assert(len == list.size());

    for ( unsigned n = 0; n < len; ++n )
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
    return ss && ( *ss >> tok );
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

