//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// author Chris Green <cmg@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>

#include "extract.h"

#include "framework/ips_option.h"
#include "log/messages.h"
#include "utils/snort_bounds.h"
#include "utils/util_cstring.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#include "service_inspectors/dce_rpc/dce_common.h"
#endif

using namespace snort;
using namespace std;

/* Storage for extracted variables */
static string variable_names[NUM_IPS_OPTIONS_VARS];
static THREAD_LOCAL uint32_t extracted_values[NUM_IPS_OPTIONS_VARS];
static THREAD_LOCAL uint8_t extracted_values_cnt = 0;

namespace snort
{

/* Given a variable name, retrieve its index.*/
int8_t GetVarByName(const char* name)
{
    int i;

    if (name == nullptr)
        return IPS_OPTIONS_NO_VAR;

    for (i = 0; i < extracted_values_cnt; i++)
    {
        if (variable_names[i] == name)
            return i;
    }

    return IPS_OPTIONS_NO_VAR;
}

/* Add a variable's name to the variable_names array
   Returns: variable index
*/
int8_t AddVarNameToList(const char* name)
{
    int i;

    for (i = 0; i < extracted_values_cnt; i++)
    {
        if (variable_names[i] == name)
            return i;
    }

    if (extracted_values_cnt < NUM_IPS_OPTIONS_VARS)
    {
        variable_names[i] = string(name);
        extracted_values_cnt++;
        return i;
    }

    return IPS_OPTIONS_NO_VAR;
}

void ClearIpsOptionsVars()
{
    extracted_values_cnt = 0;
}

/* Setters & Getters for extracted values
   Note: extracted_values_cnt is correct only during parsing, and not during eval. It shouldn't be
  used at this point */
int GetVarValueByIndex(uint32_t* dst, uint8_t var_number)
{
    if (dst == nullptr or var_number >= NUM_IPS_OPTIONS_VARS)
        return IPS_OPTIONS_NO_VAR;

    *dst = extracted_values[var_number];

    return 0;
}

int SetVarValueByIndex(uint32_t value, uint8_t var_number)
{
    if (var_number >= NUM_IPS_OPTIONS_VARS)
        return IPS_OPTIONS_NO_VAR;

    extracted_values[var_number] = value;

    return 0;
}

void set_byte_order(uint8_t& order, uint8_t flag, const char* opt)
{
    if (order)
        ParseWarning(WARN_RULES, "%s specifies multiple byte orders, using last", opt);

    order = flag;
}

#define TEXTLEN  (PARSELEN + 1)

/**
 * Grab a binary representation of data from a buffer
 *
 * This method will read either a big or little endian value in binary
 * data from the packet and return an uint32_t value.
 *
 * @param endianness value to read the byte as
 * @param bytes_to_grab how many bytes should we grab from the packet
 * @param data pointer to where to grab the data from
 * @param start pointer to start range of buffer
 * @param end pointer to end range of buffer
 * @param value pointer to store data in
 *
 * @returns 0 on success, otherwise failure
 */
int byte_extract(int endianness, int bytes_to_grab, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end,
    uint32_t* value)
{
    if (endianness != ENDIAN_LITTLE and endianness != ENDIAN_BIG)
        return -2; /* we only support 2 byte formats */

    /* make sure the data to grab stays in bounds */
    if (!inBounds(start,end,ptr + (bytes_to_grab - 1)))
        return -3;

    if (!inBounds(start,end,ptr))
        return -3;

    /*
     * We only support grabbing 1, 2, or 4 bytes of binary data.
     * And now, due to popular demand, 3 bytes!
     */
    switch (bytes_to_grab)
    {
    case 1:
        *value =  (*ptr) & 0xFF;
        break;
    case 2:
        if (endianness == ENDIAN_LITTLE)
        {
            *value = (*ptr) & 0xFF;
            *value |= (*(ptr + 1) & 0xFF) << 8;
        }
        else
        {
            *value = ((*ptr) & 0xFF) << 8;
            *value |= (*(ptr + 1)) & 0xFF;
        }
        break;
    case 3:
        if (endianness == ENDIAN_LITTLE)
        {
            *value = (*ptr) & 0xFF;
            *value |= ((*(ptr + 1)) & 0xFF) << 8;
            *value |= ((*(ptr + 2)) & 0xFF) << 16;
        }
        else
        {
            *value = ((*ptr) & 0xFF) << 16;
            *value |= ((*(ptr + 1)) & 0xFF) << 8;
            *value |= (*(ptr + 2)) & 0xFF;
        }
        break;
    case 4:
        if (endianness == ENDIAN_LITTLE)
        {
            *value = (*ptr) & 0xFF;
            *value |= ((*(ptr + 1)) & 0xFF) << 8;
            *value |= ((*(ptr + 2)) & 0xFF) << 16;
            *value |= ((*(ptr + 3)) & 0xFF) << 24;
        }
        else
        {
            *value =  ((*ptr) & 0xFF) << 24;
            *value |= ((*(ptr + 1)) & 0xFF) << 16;
            *value |= ((*(ptr + 2)) & 0xFF) << 8;
            *value |= (*(ptr + 3)) & 0xFF;
        }
        break;
    default:
        /* unknown type */
        return -1;
    }

    return 0;
}

/**
 * Grab a string representation of data from a buffer
 *
 * @param base base representation for data: -> man stroul()
 * @param bytes_to_grab how many bytes should we grab from the packet
 * @param data pointer to where to grab the data from
 * @param start pointer to start range of buffer
 * @param end pointer to end range of buffer
 * @param value pointer to store data in
 *
 * @returns 0 on success, otherwise failure
 */
int string_extract(int bytes_to_grab, int base, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end, uint32_t* value)
{
    char byte_array[TEXTLEN];
    char* parse_helper;
    int x; /* counter */

    if (bytes_to_grab > (TEXTLEN - 1) or bytes_to_grab <= 0)
        return -1;

    /* make sure the data to grab stays in bounds */
    if (!inBounds(start,end,ptr + (bytes_to_grab - 1)))
        return -3;

    if (!inBounds(start,end,ptr))
        return -3;

    for (x=0; x<bytes_to_grab; x++)
        byte_array[x] = *(ptr+x);

    byte_array[bytes_to_grab] = '\0';

    if (SnortStrToU32(byte_array, &parse_helper, value, base) != 0)
        return -1;

#ifdef TEST_BYTE_EXTRACT
    printf("[----]\n");
    for (x=0; (x<TEXTLEN) and (byte_array[x] != '\0'); x++)
        printf("%c", byte_array[x]);
    printf("\n");

    printf("converted value: 0x%08X (%u) %s\n", *value, *value, (char*)byte_array);
#endif /* TEST_BYTE_EXTRACT */
    /* Return the number of bytes actually extracted */
    return(parse_helper - byte_array);
}

void set_cursor_bounds(const ByteData& settings, const Cursor& c,
    const uint8_t*& start, const uint8_t*& ptr, const uint8_t*& end)
{
    start = c.buffer();
    end = start + c.size();

    ptr = settings.relative_flag ? c.start() : c.buffer();
    ptr += settings.offset;
}

int32_t data_extraction(const ByteData& settings, Packet* p,
    uint32_t& result_var, const uint8_t* start,
    const uint8_t* ptr, const uint8_t* end)
{
    if (p == nullptr)
        return IpsOption::NO_MATCH;

    // check bounds
    if (ptr < start or ptr >= end)
        return IpsOption::NO_MATCH;

    uint8_t endian = settings.endianness;
    if (settings.endianness == ENDIAN_FUNC)
    {
        if (!p->endianness or
            !p->endianness->get_offset_endianness(ptr - p->data, endian))
            return IpsOption::NO_MATCH;
    }

    // do the extraction
    int32_t bytes_read = 0;
    uint32_t value = 0;
    if (!settings.string_convert_flag)
    {
        int ret = 0;
        ret = byte_extract(endian, settings.bytes_to_extract, ptr, start, end, &value);
        if (ret < 0)
            return IpsOption::NO_MATCH;

        bytes_read = settings.bytes_to_extract;
    }
    else
    {
        unsigned len = end - ptr;

        if (len > settings.bytes_to_extract)
            len = settings.bytes_to_extract;

        bytes_read = string_extract(len, settings.base, ptr, start, end, &value);
        if (bytes_read < 0)
            return IpsOption::NO_MATCH;
    }

    if (settings.bitmask_val != 0)
    {
        uint32_t num_tailing_zeros_bitmask =
            getNumberTailingZerosInBitmask(settings.bitmask_val);
        value = value & settings.bitmask_val;
        if (value and num_tailing_zeros_bitmask)
            value = value >> num_tailing_zeros_bitmask;
    }

    result_var = value;
    return bytes_read;
}

int32_t extract_data(const ByteData& settings, const Cursor& c, Packet* p,
    uint32_t& result_var)
{
    const uint8_t* start = nullptr;
    const uint8_t* ptr = nullptr;
    const uint8_t* end = nullptr;
    set_cursor_bounds(settings, c, start, ptr, end);
    return data_extraction(settings, p, result_var, start, ptr, end);
}

uint32_t getNumberTailingZerosInBitmask(uint32_t bitmask)
{
    if (bitmask == 0)
        return 32;

    return (ffs(bitmask)-1);
}

uint8_t numBytesInBitmask(uint32_t bitmask_value)
{
    uint8_t num_bytes;
    if (bitmask_value <= 0xFF)
        num_bytes = 1;
    else if (bitmask_value <= 0xFFFF)
        num_bytes = 2;
    else if (bitmask_value <= 0xFFFFFF)
        num_bytes = 3;
    else
        num_bytes = 4;

    return num_bytes;
}

} // namespace snort

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST

#define INITIALIZE(obj, bytes_to_extract_value, offset_value, relative_flag_value, \
    string_convert_flag_value, base_value, endianness_value, bitmask_val_value) \
    obj.base = base_value; \
    obj.bitmask_val = bitmask_val_value; \
    obj.bytes_to_extract = bytes_to_extract_value; \
    obj.offset = offset_value; \
    obj.endianness = endianness_value; \
    obj.relative_flag = relative_flag_value; \
    obj.string_convert_flag = string_convert_flag_value

TEST_CASE("ips options bitmask utils")
{
    // numBytesInBitmask tests
    REQUIRE((numBytesInBitmask(0x1f) == 1));
    REQUIRE((numBytesInBitmask(0x1ff) == 2));
    REQUIRE((numBytesInBitmask(0x1ffff) == 3));
    REQUIRE((numBytesInBitmask(0x1ffffff) == 4));

    // getNumberTailingZerosInBitmask tests
    REQUIRE((getNumberTailingZerosInBitmask(0x1f) == 0));
    REQUIRE((getNumberTailingZerosInBitmask(0x1e) == 1));
    REQUIRE((getNumberTailingZerosInBitmask(0x14) == 2));
    REQUIRE((getNumberTailingZerosInBitmask(0x10) == 4));
    REQUIRE((getNumberTailingZerosInBitmask(0x100) == 8));
    REQUIRE((getNumberTailingZerosInBitmask(0x10000) == 16));
    REQUIRE((getNumberTailingZerosInBitmask(0x20000) == 17));
    REQUIRE((getNumberTailingZerosInBitmask(0) == 32));
}

TEST_CASE("ips options vars")
{
    // Fill up array
    int8_t ind1 = AddVarNameToList("OFFSET");
    REQUIRE((ind1 == 0));

    int8_t ind2 = AddVarNameToList("VALUE");
    REQUIRE((ind2 == 1));

    int8_t ind3 = AddVarNameToList("VAR3");
    REQUIRE((ind3 == IPS_OPTIONS_NO_VAR));

    // Insert same name twice
    REQUIRE((AddVarNameToList("VALUE") == 1));
    REQUIRE((GetVarByName("VALUE") == 1));

    // Try to insert to a full array
    REQUIRE((AddVarNameToList("VALUE1") == IPS_OPTIONS_NO_VAR));
    // Try to get a name that wasn't inserted
    REQUIRE((GetVarByName("VALUE1") == IPS_OPTIONS_NO_VAR));

    // Go over error path - nullptr / bad index
    REQUIRE((GetVarByName(nullptr) == IPS_OPTIONS_NO_VAR));
    REQUIRE((GetVarValueByIndex(nullptr, 0) == IPS_OPTIONS_NO_VAR));
    uint32_t dst;
    REQUIRE((GetVarValueByIndex(&dst, NUM_IPS_OPTIONS_VARS) == IPS_OPTIONS_NO_VAR));
    REQUIRE((SetVarValueByIndex(0, NUM_IPS_OPTIONS_VARS) == IPS_OPTIONS_NO_VAR));
}

TEST_CASE("set_cursor_bounds", "[byte_extraction_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 010 12345 0x75";
    p.dsize = 21;
    Cursor c(&p);
    const uint8_t* start = nullptr;
    const uint8_t* ptr = nullptr;
    const uint8_t* end = nullptr;

    SECTION("4 bytes read, no offset")
    {
        ByteData settings;
        INITIALIZE(settings, 4, 0, 0, 0, 0, ENDIAN_BIG, 0);
        set_cursor_bounds(settings, c, start, ptr, end);
        CHECK(start == p.data);
        CHECK(ptr == p.data);
        CHECK(end == p.data + 21);
    }
    SECTION("4 byte read, offset = 4")
    {
        ByteData settings;
        INITIALIZE(settings, 4, 4, 0, 0, 0, ENDIAN_BIG, 0);
        set_cursor_bounds(settings, c, start, ptr, end);
        CHECK(start == p.data);
        CHECK(ptr == p.data + 4);
        CHECK(end == p.data + 21);
    }
    SECTION("4 bytes read, cursor move without relative flag")
    {
        c.set_pos(3);
        ByteData settings;
        INITIALIZE(settings, 4, 0, 0, 0, 0, ENDIAN_BIG, 0);
        set_cursor_bounds(settings, c, start, ptr, end);
        CHECK(start == p.data);
        CHECK(ptr == p.data);
        CHECK(end == p.data + 21);
    }
    SECTION("4 bytes read, cursor move with relative flag")
    {
        c.set_pos(3);
        ByteData settings;
        INITIALIZE(settings, 4, 0, true, 0, 0, ENDIAN_BIG, 0);
        set_cursor_bounds(settings, c, start, ptr, end);
        CHECK(start == p.data);
        CHECK(ptr == p.data + 3);
        CHECK(end == p.data + 21);
    }
}

TEST_CASE("extract_data valid", "[byte_extraction_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 010 12345 0x75";
    p.dsize = 21;
    Cursor c(&p);
    uint32_t res = 0;

    SECTION("1 byte read, all - off")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 1);
        CHECK(res == 76);
    }
    SECTION("2 bytes read, all - off")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 19567);
    }
    SECTION("3 bytes read, all - off")
    {
        ByteData settings;
        INITIALIZE(settings, 3, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 3);
        CHECK(res == 5009266);
    }
    SECTION("4 bytes read, all - off")
    {
        ByteData settings;
        INITIALIZE(settings, 4, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 4);
        CHECK(res == 1282372197);
    }
    SECTION("1 byte read, offset 3")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 3, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 1);
        CHECK(res == 101);
    }
    SECTION("1 byte read, offset 3, relative")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 3, 1, 0, 0, ENDIAN_BIG, 0);
        c.set_pos(3);
        CHECK(extract_data(settings, c, &p, res) == 1);
        CHECK(res == 48);
    }
    SECTION("cursor 3, 1 byte read, offset -3, relative")
    {
        ByteData settings;
        INITIALIZE(settings, 1, -3, 1, 0, 0, ENDIAN_BIG, 0);
        c.set_pos(3);
        CHECK(extract_data(settings, c, &p, res) == 1);
        CHECK(res == 76);
    }
    SECTION("1 byte read, offset 6, string conversion, base 10")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 10, 0, 1, 10, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 1);
        CHECK(res == 1);
    }
    SECTION("2 bytes read, offset 6, string conversion, base 8 without prefix")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 10, 0, 1, 8, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 10);
    }
    SECTION("2 bytes read, offset 6, string conversion, base 10")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 10, 0, 1, 10, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 12);
    }
    SECTION("2 bytes read, offset 6, string conversion, base 16 without prefix")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 10, 0, 1, 16, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 18);
    }
    SECTION("3 bytes read, offset 6, string conversion, base 8 with prefix")
    {
        ByteData settings;
        INITIALIZE(settings, 3, 6, 0, 1, 8, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 3);
        CHECK(res == 8);
    }
    SECTION("4 bytes read, offset 6, string conversion, base 16 with prefix")
    {
        ByteData settings;
        INITIALIZE(settings, 4, 16, 0, 1, 16, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == 4);
        CHECK(res == 117);
    }
    SECTION("2 byte read, bitmask 1100110011100011")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 0, 0, 0, 0, ENDIAN_BIG, 52451);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 19555);
    }
    SECTION("2 byte read, bitmask 1100110011100000")
    {
        ByteData settings;
        INITIALIZE(settings, 2, 0, 0, 0, 0, ENDIAN_BIG, 52448);
        CHECK(extract_data(settings, c, &p, res) == 2);
        CHECK(res == 611);
    }
    SECTION("4 bytes read, ENDIAN_LITTLE")
    {
        ByteData settings;
        INITIALIZE(settings, 4, 0, 0, 0, 0, ENDIAN_LITTLE, 0);
        CHECK(extract_data(settings, c, &p, res) == 4);
        CHECK(res == 1701998412);
    }
    SECTION("4 bytes read, ENDIAN_FUNC, packet.endianness " \
        "= DCERPC_BO_FLAG__LITTLE_ENDIAN")
    {
        DceEndianness* auto_endian = new DceEndianness();
        auto_endian->hdr_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        auto_endian->data_byte_order = DCERPC_BO_FLAG__LITTLE_ENDIAN;
        p.endianness = auto_endian;
        ByteData settings;
        INITIALIZE(settings, 4, 0, 0, 0, 0, ENDIAN_FUNC, 0);
        CHECK(extract_data(settings, c, &p, res) == 4);
        CHECK(res == 1701998412);
    }
}

TEST_CASE("extract_data invalid", "[byte_extraction_tests]")
{
    Packet p;
    p.data = (const uint8_t*)"Lorem 9876";
    p.dsize = 11;
    Cursor c(&p);
    uint32_t res = 0;

    SECTION("packet = nullptr")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, nullptr, res) == IpsOption::NO_MATCH);
    }
    SECTION("read more than 4 bytes")
    {
        ByteData settings;
        INITIALIZE(settings, 6, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("check bounds of packet, offset > packet size")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 20, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("negative offset, without relative flag")
    {
        ByteData settings;
        INITIALIZE(settings, 1, -20, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("negative offset, out of bounds")
    {
        ByteData settings;
        INITIALIZE(settings, 1, -20, 1, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("check bounds of packet, offset > packet size, empty packet")
    {
        p.data = (const uint8_t*)"";
        p.dsize = 0;
        Cursor c2(&p);
        ByteData settings;
        INITIALIZE(settings, 1, 20, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c2, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("check bounds of packet, read 2 bytes, empty packet")
    {
        p.data = (const uint8_t*)"";
        p.dsize = 0;
        Cursor c2(&p);
        ByteData settings;
        INITIALIZE(settings, 2, 0, 0, 0, 0, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c2, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("ENDIAN_FUNC, without definition of endianness in packet")
    {
        ByteData settings;
        INITIALIZE(settings, 3, 0, 0, 0, 0, ENDIAN_FUNC, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("conversion from string, decimal number, base = 8")
    {
        ByteData settings;
        INITIALIZE(settings, 3, 6, 0, 1, 8, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("conversion from string but the input is symbol")
    {
        ByteData settings;
        INITIALIZE(settings, 1, 0, 0, 1, 10, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
    SECTION("cursor behind the packet size")
    {
        c.set_pos(15);
        ByteData settings;
        INITIALIZE(settings, 1, 0, 0, 1, 10, ENDIAN_BIG, 0);
        CHECK(extract_data(settings, c, &p, res) == IpsOption::NO_MATCH);
    }
}
#endif
