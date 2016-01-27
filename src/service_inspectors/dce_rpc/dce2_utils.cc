//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2008-2013 Sourcefire, Inc.
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

#include "dce2_utils.h"


/********************************************************************
 * Function: DCE2_GetValue()
 *
 * Parses integer values up to 64 bit unsigned.  Stores the value
 * parsed in memory passed in as an argument.
 *
 * Arguments:
 *  char *
 *      Pointer to the first character in the string to parse.
 *  char *
 *      Pointer to the byte after the last character of
 *      the string to parse.
 *  void *
 *      Pointer to the memory where the parsed integer should
 *      be stored on successful parsing.
 *  int
 *      Non-zero if the parsed value should be negated.
 *      Zero if the parsed value should not be negated.
 *  DCE2_IntType
 *      The type of integer we want to parse and the integer type
 *      that the pointer that the parsed value will be put in is.
 *  uint8_t
 *      The base that the parsed value should be converted to.
 *      Only 8, 10 and 16 are supported.
 *
 * Returns:
 *  DCE2_Ret
 *      DCE2_RET__SUCCESS if we were able to successfully parse the
 *          integer to the type specified.
 *      DCE2_RET__ERROR if an error occured in parsing.
 *
 ********************************************************************/
DCE2_Ret DCE2_GetValue(char* start, char* end, void* int_value, int negate,
    DCE2_IntType int_type, uint8_t base)
{
    uint64_t value = 0;
    uint64_t place = 1;
    uint64_t max_value = 0;

    if ((end == NULL) || (start == NULL) || (int_value == NULL))
        return DCE2_RET__ERROR;

    if (start >= end)
        return DCE2_RET__ERROR;

    for (end = end - 1; end >= start; end--)
    {
        uint64_t add_value;
        char c = *end;

        if ((base == 16) && !isxdigit((int)c))
            return DCE2_RET__ERROR;
        else if ((base != 16) && !isdigit((int)c))
            return DCE2_RET__ERROR;

        if (isdigit((int)c))
            add_value = (uint64_t)(c - '0') * place;
        else
            add_value = (uint64_t)((toupper((int)c) - 'A') + 10) * place;

        if ((UINT64_MAX - value) < add_value)
            return DCE2_RET__ERROR;

        value += add_value;
        place *= base;
    }

    switch (int_type)
    {
    case DCE2_INT_TYPE__INT8:
        max_value = ((UINT8_MAX - 1) / 2);
        if (negate)
            max_value++;
        break;
    case DCE2_INT_TYPE__UINT8:
        max_value = UINT8_MAX;
        break;
    case DCE2_INT_TYPE__INT16:
        max_value = ((UINT16_MAX - 1) / 2);
        if (negate)
            max_value++;
        break;
    case DCE2_INT_TYPE__UINT16:
        max_value = UINT16_MAX;
        break;
    case DCE2_INT_TYPE__INT32:
        max_value = ((UINT32_MAX - 1) / 2);
        if (negate)
            max_value++;
        break;
    case DCE2_INT_TYPE__UINT32:
        max_value = UINT32_MAX;
        break;
    case DCE2_INT_TYPE__INT64:
        max_value = ((UINT64_MAX - 1) / 2);
        if (negate)
            max_value++;
        break;
    case DCE2_INT_TYPE__UINT64:
        max_value = UINT64_MAX;
        break;
    }

    if (value > max_value)
        return DCE2_RET__ERROR;

    if (negate)
        value *= -1;

    switch (int_type)
    {
    case DCE2_INT_TYPE__INT8:
        *(int8_t*)int_value = (int8_t)value;
        break;
    case DCE2_INT_TYPE__UINT8:
        *(uint8_t*)int_value = (uint8_t)value;
        break;
    case DCE2_INT_TYPE__INT16:
        *(int16_t*)int_value = (int16_t)value;
        break;
    case DCE2_INT_TYPE__UINT16:
        *(uint16_t*)int_value = (uint16_t)value;
        break;
    case DCE2_INT_TYPE__INT32:
        *(int32_t*)int_value = (int32_t)value;
        break;
    case DCE2_INT_TYPE__UINT32:
        *(uint32_t*)int_value = (uint32_t)value;
        break;
    case DCE2_INT_TYPE__INT64:
        *(int64_t*)int_value = (int64_t)value;
        break;
    case DCE2_INT_TYPE__UINT64:
        *(uint64_t*)int_value = (uint64_t)value;
        break;
    }

    return DCE2_RET__SUCCESS;
}

