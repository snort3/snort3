//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "extract.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"

#define TEXTLEN  (PARSELEN + 1)

/**
 * Grab a binary representation of data from a buffer
 *
 * This method will read either a big or little endian value in binary
 * data from the packet and return an uint32_t value.
 *
 * @param endianess value to read the byte as
 * @param bytes_to_grab how many bytes should we grab from the packet
 * @param data pointer to where to grab the data from
 * @param start pointer to start range of buffer
 * @param end pointer to end range of buffer
 * @param value pointer to store data in
 *
 * @returns 0 on success, otherwise failure
 */
int byte_extract(int endianess, int bytes_to_grab, const uint8_t* ptr,
    const uint8_t* start, const uint8_t* end,
    uint32_t* value)
{
    if (endianess != ENDIAN_LITTLE && endianess != ENDIAN_BIG)
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
        if (endianess == ENDIAN_LITTLE)
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
        if (endianess == ENDIAN_LITTLE)
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
        if (endianess == ENDIAN_LITTLE)
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
    for (x=0; (x<=TEXTLEN) && (byte_array[x] != '\0'); x++)
        printf("%c", byte_array[x]);
    printf("\n");

    printf("converted value: 0x%08X (%u) %s\n", *value, *value, (char*)byte_array);
#endif /* TEST_BYTE_EXTRACT */
    return(parse_helper - byte_array);  /* Return the number of bytes actually extracted */
}

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

