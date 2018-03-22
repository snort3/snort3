//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_utils.h"

#include "utils/safec.h"
#include "utils/util.h"

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
 *      DCE2_RET__ERROR if an error occurred in parsing.
 *
 ********************************************************************/
DCE2_Ret DCE2_GetValue(const char* start, char* end, void* int_value, int negate,
    DCE2_IntType int_type, uint8_t base)
{
    uint64_t value = 0;
    uint64_t place = 1;
    uint64_t max_value = 0;

    if ((end == nullptr) || (start == nullptr) || (int_value == nullptr))
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

const char* DCE2_UuidToStr(
    const Uuid* uuid, DceRpcBoFlag byte_order, char (& uuid_buf)[50])
{
    snprintf(uuid_buf, DCE2_UUID_BUF_SIZE,
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        DceRpcHtonl(&uuid->time_low, byte_order),
        DceRpcHtons(&uuid->time_mid, byte_order),
        DceRpcHtons(&uuid->time_high_and_version, byte_order),
        uuid->clock_seq_and_reserved, uuid->clock_seq_low,
        uuid->node[0], uuid->node[1], uuid->node[2],
        uuid->node[3], uuid->node[4], uuid->node[5]);

    uuid_buf[DCE2_UUID_BUF_SIZE - 1] = '\0';
    return uuid_buf;
}


DCE2_Buffer* DCE2_BufferNew(uint32_t initial_size, uint32_t min_add_size)
{
    DCE2_Buffer* buf = (DCE2_Buffer*)snort_calloc(sizeof(DCE2_Buffer));

    if (initial_size != 0)
        buf->data = (uint8_t*)snort_calloc(initial_size);

    buf->size = initial_size;
    buf->len = 0;
    buf->min_add_size = min_add_size;
    buf->offset = 0;

    return buf;
}

void* DCE2_ReAlloc(void* old_mem, uint32_t old_size, uint32_t new_size)
{
    void* new_mem;

    if (old_mem == nullptr)
    {
        return nullptr;
    }
    else if (new_size < old_size)
    {
        return nullptr;
    }
    else if (new_size == old_size)
    {
        return old_mem;
    }

    new_mem = snort_calloc(new_size);

    memcpy_s(new_mem, new_size, old_mem, old_size);

    snort_free(old_mem);

    return new_mem;
}

DCE2_Ret DCE2_BufferAddData(DCE2_Buffer* buf, const uint8_t* data,
    uint32_t data_len, uint32_t data_offset, DCE2_BufferMinAddFlag mflag)
{
    if ((buf == nullptr) || (data == nullptr))
        return DCE2_RET__ERROR;

    /* Return success for this since ultimately nothing _was_ added */
    if (data_len == 0)
        return DCE2_RET__SUCCESS;

    if (buf->data == nullptr)
    {
        uint32_t size = data_offset + data_len;

        if ((size < buf->min_add_size) && (mflag == DCE2_BUFFER_MIN_ADD_FLAG__USE))
            size = buf->min_add_size;

        buf->data = (uint8_t*)snort_calloc(size);
        buf->size = size;
    }
    else if ((data_offset + data_len) > buf->size)
    {
        uint8_t* tmp;
        uint32_t new_size = data_offset + data_len;

        if (((new_size - buf->size) < buf->min_add_size) && (mflag ==
            DCE2_BUFFER_MIN_ADD_FLAG__USE))
            new_size = buf->size + buf->min_add_size;

        tmp = (uint8_t*)DCE2_ReAlloc(buf->data, buf->size, new_size);
        if (tmp == nullptr)
            return DCE2_RET__ERROR;

        buf->data = tmp;
        buf->size = new_size;
    }

    if (data_len > buf->size - data_offset)
        return DCE2_RET__ERROR;

    memcpy_s(buf->data + data_offset, buf->size - data_offset, data, data_len);

    if ((data_offset + data_len) > buf->len)
        buf->len = data_offset + data_len;

    return DCE2_RET__SUCCESS;
}

void DCE2_BufferDestroy(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return;

    if (buf->data != nullptr)
        snort_free((void*)buf->data);

    snort_free((void*)buf);
}

