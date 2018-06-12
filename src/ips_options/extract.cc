//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"
#include "utils/snort_bounds.h"
#include "utils/util_cstring.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
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
    if (dst == nullptr || var_number >= NUM_IPS_OPTIONS_VARS)
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
    if ( order )
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
    if (endianness != ENDIAN_LITTLE && endianness != ENDIAN_BIG)
    {
        /* we only support 2 byte formats */
        return -2;
    }

    /* make sure the data to grab stays in bounds */
    if (!inBounds(start,end,ptr + (bytes_to_grab - 1)))
    {
        return -3;
    }

    if (!inBounds(start,end,ptr))
    {
        return -3;
    }

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
    const uint8_t* start, const uint8_t* end,
    uint32_t* value)
{
    char byte_array[TEXTLEN];
    char* parse_helper;
    int x; /* counter */

    if (bytes_to_grab > (TEXTLEN - 1) || bytes_to_grab <= 0)
    {
        return -1;
    }

    /* make sure the data to grab stays in bounds */
    if (!inBounds(start,end,ptr + (bytes_to_grab - 1)))
    {
        return -3;
    }

    if (!inBounds(start,end,ptr))
    {
        return -3;
    }

    for (x=0; x<bytes_to_grab; x++)
    {
        byte_array[x] = *(ptr+x);
    }

    byte_array[bytes_to_grab] = '\0';

    if (SnortStrToU32(byte_array, &parse_helper, value, base) != 0)
        return -1;

#ifdef TEST_BYTE_EXTRACT
    printf("[----]\n");
    for (x=0; (x<TEXTLEN) && (byte_array[x] != '\0'); x++)
        printf("%c", byte_array[x]);
    printf("\n");

    printf("converted value: 0x%08X (%u) %s\n", *value, *value, (char*)byte_array);
#endif /* TEST_BYTE_EXTRACT */
    return(parse_helper - byte_array);  /* Return the number of bytes actually extracted */
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
    if ( bitmask_value <= 0xFF )
        num_bytes = 1;
    else if ( bitmask_value <= 0xFFFF )
        num_bytes = 2;
    else if ( bitmask_value <= 0xFFFFFF )
        num_bytes = 3;
    else
        num_bytes = 4;

    return num_bytes;
}

} // namespace snort

#ifdef UNIT_TEST
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
    REQUIRE((ind3 == 2));

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

#endif

#ifdef TEST_BYTE_EXTRACT
#include <stdio.h>

void test_extract()
{
    int i;
    uint32_t ret;

    uint8_t value1[2];
    uint8_t value2[2];
    uint8_t value3[4];

    value1[0] = 0;
    value1[1] = 0xff;

    value2[0] = 0xff;
    value2[1] = 0x01;

    value3[0] = 0xff;
    value3[1] = 0xff;
    value3[2] = 0x00;
    value3[3] = 0x00;

    if (byte_extract(ENDIAN_BIG, 2, value1, value1, value1 + 2, &ret))
    {
        printf("test 1 failed\n");
    }
    else
    {
        printf("test 1: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 2, value1, value1, value1 + 2, &ret))
    {
        printf("test 2 failed\n");
    }
    else
    {
        printf("test 2: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 2, value1 + 2, value1, value1 + 2, &ret))
    {
        printf("test 3 failed correctly\n");
    }
    else
    {
        printf("test 3: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_BIG, 2, value2, value2, value2 + 2, &ret))
    {
        printf("test 1 failed\n");
    }
    else
    {
        printf("test 1: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 2, value2, value2, value2 + 2, &ret))
    {
        printf("test 2 failed\n");
    }
    else
    {
        printf("test 2: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 2, value2 + 2, value2, value2 + 2, &ret))
    {
        printf("test 3 failed correctly\n");
    }
    else
    {
        printf("test 3: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_BIG, 4, value3, value3, value3 + 4, &ret))
    {
        printf("test 1 failed\n");
    }
    else
    {
        printf("test 1: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 4, value3, value3, value3 + 4, &ret))
    {
        printf("test 2 failed\n");
    }
    else
    {
        printf("test 2: value: %x %u\n", ret, ret);
    }

    if (byte_extract(ENDIAN_LITTLE, 4, value3 + 2, value3, value3 + 4, &ret))
    {
        printf("test 3 failed correctly\n");
    }
    else
    {
        printf("test 3: value: %x %u\n", ret, ret);
    }

    printf("-----------------------------\n");

    for (i=0; i<10; i++)
    {
        if (byte_extract(ENDIAN_LITTLE, 4, value3 + i, value3, value3 + 4, &ret))
        {
            printf("[loop] %d failed correctly\n", i);
        }
        else
        {
            printf("[loop] value: %x %x\n", ret, *(uint32_t*)&value3);
        }
    }
}

void test_string()
{
    char* stringdata = "21212312412";
    int datalen = strlen(stringdata);
    uint32_t ret;

    if (string_extract(4, 10, stringdata,  stringdata, stringdata + datalen,  &ret) < 0)
    {
        printf("TS1: Failed\n");
    }
    else
    {
        printf("TS1: value %x %u\n", ret, ret);
    }

    if (string_extract(10, 10, stringdata,  stringdata, stringdata + datalen,  &ret) < 0)
    {
        printf("TS2: Failed\n");
    }
    else
    {
        printf("TS2: value %x %u\n", ret, ret);
    }

    if (string_extract(9, 10, stringdata,  stringdata, stringdata + datalen,  &ret) < 0)
    {
        printf("TS3: Failed\n");
    }
    else
    {
        printf("TS3: value %x %u\n", ret, ret);
    }

    if (string_extract(19, 10, stringdata,  stringdata, stringdata + datalen,  &ret) < 0)
    {
        printf("TS4: Failed Normally\n");
    }
    else
    {
        printf("TS4: value %x %u\n", ret, ret);
    }
}

int main()
{
    test_extract();
    test_string();
    return 0;
}

#endif /* TEST_BYTE_EXTRACT */

