//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// value.h author Russ Combs <rucombs@cisco.com>

#ifndef VALUE_H
#define VALUE_H

// Value is used to represent Lua bool, number, and string.

#include <algorithm>
#include <cstring>
#include <sstream>

#include "framework/bits.h"
#include "framework/parameter.h"
#include "main/snort_types.h"

namespace snort
{
struct SfCidr;
struct SfIp;

class SO_PUBLIC Value
{
public:
    static const unsigned mask_bits = 52; // ieee 754 significand
    enum ValueType { VT_BOOL, VT_NUM, VT_UNUM, VT_STR, VT_REAL };

    Value(bool b)
    { set(b); }

    Value(double d)
    { set(d); }

    Value(int64_t i)
    { set(i); }

    Value(uint64_t u)
    { set(u); }

    Value(const char* s)
    { set(s); set_origin(s); }

    Value(const Value& v) :
        type(v.type),
        unum(v.unum),
        num(v.num),
        real(v.real),
        str(v.str),
        origin_str(v.origin_str),
        ss(nullptr),
        param(v.param)
    {}

    Value& operator=(const Value& v)
    {
        if ( this == &v )
            return *this;

        delete ss;
        ss = nullptr;

        type = v.type;
        num = v.num;
        unum = v.unum;
        real = v.real;
        str = v.str;
        origin_str = v.origin_str;
        param = v.param;

        return *this;
    }

    ValueType get_type() const
    { return type; }

    ~Value()
    { delete ss; }

    void set(bool b)
    { type = VT_BOOL; unum = b ? 1 : 0; }

    void set(double d)
    { type = VT_REAL; real = d; }

    void set(uint64_t n)
    { type = VT_UNUM; unum = n; }

    void set(int64_t n)
    { type = VT_NUM; num = n; }

    void set(const char* s)
    { type = VT_STR; str = s; }

    void set_origin(const char* val)
    { origin_str = val; }

    void set(const uint8_t* s, unsigned len)
    { type = VT_STR; str.assign((const char*)s, len); }

    void set(const Parameter* p)
    { param = p; }

    void set_enum(unsigned u)
    { type = VT_UNUM; unum = u; }

    void set_aux(uint64_t u)
    { type = VT_UNUM; unum = u; }

    const char* get_name() const
    { return param ? param->name : nullptr; }

    bool is(const char* s) const
    { return param ? !strcmp(param->name, s) : false; }

    bool has_default() const
    { return param ? param->deflt != nullptr : false; }

    bool get_bool() const
    { return 0 != ((VT_REAL == type) ? real : unum); }

    size_t get_size() const
    { return (VT_REAL == type) ? (size_t)real : ((VT_UNUM == type) ? (size_t)unum : (size_t)num); }

    uint8_t get_uint8() const
    { return (VT_REAL == type) ? (uint8_t)real : ((VT_UNUM == type) ? (uint8_t)unum : (uint8_t)num); }

    int16_t get_int16() const
    { return (VT_REAL == type) ? (int16_t)real : ((VT_UNUM == type) ? (int16_t)unum : (int16_t)num); }

    uint16_t get_uint16() const
    { return (VT_REAL == type) ? (uint16_t)real : ((VT_UNUM == type) ? (uint16_t)unum : (uint16_t)num); }

    int32_t get_int32() const
    { return (VT_REAL == type) ? (int32_t)real : ((VT_UNUM == type) ? (int32_t)unum : (int32_t)num); }

    uint32_t get_uint32() const
    { return (VT_REAL == type) ? (uint32_t)real : ((VT_UNUM == type) ? (uint32_t)unum : (uint32_t)num); }

    int64_t get_int64() const
    { return (VT_REAL == type) ? (int64_t)real : ((VT_UNUM == type) ? (int64_t)unum : (int64_t)num); }

    uint64_t get_uint64() const
    { return (VT_REAL == type) ? (uint64_t)real : ((VT_UNUM == type) ? (uint64_t)unum : (uint64_t)num); }

    double get_real() const
    { return real; }

    const uint8_t* get_buffer(unsigned& n) const
    { n = (unsigned)str.size(); return (const uint8_t*)str.data(); }

    const char* get_string() const
    { return str.c_str(); }

    std::string get_as_string() const;
    Parameter::Type get_param_type() const;
    std::string get_origin_string() const;

    std::string get_unquoted_string() const
    {
        if ( str.length() < 2 )
            return str;

        std::string tmp = str;

        if ( tmp.front() == '"' and tmp.back() == '"' )
        {
            tmp.erase(0, 1);
            tmp.erase(tmp.size() - 1, 1);
        }

        return tmp;
    }

    bool strtol(long&) const;
    bool strtol(long&, const std::string&) const;
    bool strtoul(unsigned long&) const;
    bool strtoul(unsigned long&, const std::string&) const;

    bool operator==(const char* s) const
    { return str == s; }

    bool operator==(uint64_t n) const
    { return n == ((VT_UNUM == type) ? unum : (uint64_t)num); }

    bool operator==(double d) const
    { return real == d; }

    void get_bits(PortBitSet&) const;
    void get_bits(VlanBitSet&) const;
    void get_bits(ByteBitSet&) const;

    void lower()
    { std::transform(str.begin(), str.end(), str.begin(), ::tolower); }

    void upper()
    { std::transform(str.begin(), str.end(), str.begin(), ::toupper); }

    uint32_t get_ip4() const
    { return (VT_REAL == type) ? (uint32_t)real : (uint32_t)unum; }
    void get_mac(uint8_t (&mac)[6]) const;
    void get_addr(uint8_t (&addr)[16]) const;
    void get_addr_ip4(uint8_t (&addr)[4]) const;
    void get_addr_ip6(uint8_t (&addr)[16]) const;
    void get_addr(SfIp&) const;
    void get_addr(SfCidr&) const;

    void set_first_token();
    bool get_next_token(std::string&);
    bool get_next_csv_token(std::string&);

    // set/clear flag based on get_bool()
    void update_mask(uint8_t& mask, uint8_t flag, bool invert = false);
    void update_mask(uint16_t& mask, uint16_t flag, bool invert = false);
    void update_mask(uint32_t& mask, uint32_t flag, bool invert = false);
    void update_mask(uint64_t& mask, uint64_t flag, bool invert = false);

private:
    ValueType type;
    uint64_t unum = 0;
    int64_t num = 0;
    double real = 0;
    std::string str;
    std::string origin_str;
    std::stringstream* ss = nullptr;
    const Parameter* param = nullptr;
};
}
#endif

