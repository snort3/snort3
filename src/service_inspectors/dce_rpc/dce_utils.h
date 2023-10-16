//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DCE_UTILS_H
#define DCE_UTILS_H

#include <cctype>
#include <cstring>
#include "main/snort_types.h"

/********************************************************************
 * Macros
 ********************************************************************/
#define DCE2_SENTINEL (-1)
#define DCE2_CFG_TOK__END            '\0'

/********************************************************************
 * Enumerations
 ********************************************************************/
enum DCE2_Ret
{
    DCE2_RET__SUCCESS = 0,
    DCE2_RET__ERROR,
    DCE2_RET__MEMCAP,
    DCE2_RET__NOT_INSPECTED,
    DCE2_RET__INSPECTED,
    DCE2_RET__REASSEMBLE,
    DCE2_RET__SEG,
    DCE2_RET__FULL,
    DCE2_RET__FRAG,
    DCE2_RET__ALERTED,
    DCE2_RET__IGNORE,
    DCE2_RET__DUPLICATE
};

enum DCE2_TransType
{
    DCE2_TRANS_TYPE__NONE = 0,
    DCE2_TRANS_TYPE__SMB,
    DCE2_TRANS_TYPE__TCP,
    DCE2_TRANS_TYPE__UDP,
    DCE2_TRANS_TYPE__MAX
};

enum DCE2_IntType
{
    DCE2_INT_TYPE__INT8,
    DCE2_INT_TYPE__UINT8,
    DCE2_INT_TYPE__INT16,
    DCE2_INT_TYPE__UINT16,
    DCE2_INT_TYPE__INT32,
    DCE2_INT_TYPE__UINT32,
    DCE2_INT_TYPE__INT64,
    DCE2_INT_TYPE__UINT64
};

/* DCE/RPC byte order flag */
enum DceRpcBoFlag
{
    DCERPC_BO_FLAG__NONE,
    DCERPC_BO_FLAG__BIG_ENDIAN,
    DCERPC_BO_FLAG__LITTLE_ENDIAN
};
enum DCE2_BufType
{
    DCE2_BUF_TYPE__NULL,
    DCE2_BUF_TYPE__SEG,
    DCE2_BUF_TYPE__FRAG
};
enum DCE2_BufferMinAddFlag
{
    DCE2_BUFFER_MIN_ADD_FLAG__USE,
    DCE2_BUFFER_MIN_ADD_FLAG__IGNORE
};

/********************************************************************
 * Structures
 ********************************************************************/

struct Uuid
{
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_high_and_version;
    uint8_t clock_seq_and_reserved;
    uint8_t clock_seq_low;
    uint8_t node[6];
};

struct DCE2_Buffer
{
    uint8_t* data;
    uint32_t len;
    uint32_t size;
    uint32_t min_add_size;
    uint32_t offset;
};

/********************************************************************
 * Inline function prototypes
 ********************************************************************/

inline bool DCE2_IsSpaceChar(const char);
inline bool DCE2_IsConfigEndChar(const char);

inline char* DCE2_PruneWhiteSpace(char*);
inline bool DCE2_IsEmptyStr(char*);

inline int DCE2_UuidCompare(const void*, const void*);

/********************************************************************
 * Public function prototypes
 ********************************************************************/
DCE2_Ret DCE2_GetValue(const char*, char*, void*, int, DCE2_IntType, uint8_t);
DCE2_Buffer* DCE2_BufferNew(uint32_t, uint32_t);
void* DCE2_ReAlloc(void*, uint32_t, uint32_t);
DCE2_Ret DCE2_BufferAddData(DCE2_Buffer*, const uint8_t*,
    uint32_t, uint32_t, DCE2_BufferMinAddFlag);
void DCE2_BufferDestroy(DCE2_Buffer* buf);

#define DCE2_UUID_BUF_SIZE 50
const char* DCE2_UuidToStr(
    const Uuid*, DceRpcBoFlag, char (&buf)[DCE2_UUID_BUF_SIZE]);

// Determines if the character passed in is a character that
// the inspector considers a to be a space character.

inline bool DCE2_IsSpaceChar(const char c)
{
    if (isspace((int)c))
        return true;
    return false;
}

// Determines if the character passed in is a character that
// the inspector considers a to be an end of configuration
// character.

inline bool DCE2_IsConfigEndChar(const char c)
{
    if (c == DCE2_CFG_TOK__END)
        return true;
    return false;
}

// Prunes whitespace surrounding string.
// String must be 0 terminated.

inline char* DCE2_PruneWhiteSpace(char* str)
{
    char* end;

    if (str == nullptr)
        return nullptr;

    /* Put end a char before null byte */
    end = str + (strlen(str) - 1);

    while (isspace((int)*str))
        str++;

    while ((end > str) && isspace((int)*end))
    {
        *end = '\0';
        end--;
    }

    return str;
}

// Checks if string is null, empty or just spaces.
// String must be 0 terminated.

inline bool DCE2_IsEmptyStr(char* str)
{
    char* end;

    if (str == nullptr)
        return true;

    end = str + strlen(str);

    while ((str < end) && isspace((int)*str))
        str++;

    if (str == end)
        return true;

    return false;
}

inline int DCE2_UuidCompare(const void* data1, const void* data2)
{
    const Uuid* uuid1 = (const Uuid*)data1;
    const Uuid* uuid2 = (const Uuid*)data2;

    if ((uuid1 == nullptr) || (uuid2 == nullptr))
        return -1;

    if ((uuid1->time_low == uuid2->time_low) &&
        (uuid1->time_mid == uuid2->time_mid) &&
        (uuid1->time_high_and_version == uuid2->time_high_and_version) &&
        (uuid1->clock_seq_and_reserved == uuid2->clock_seq_and_reserved) &&
        (uuid1->clock_seq_low == uuid2->clock_seq_low) &&
        (memcmp(uuid1->node, uuid2->node, sizeof(uuid1->node)) == 0))
    {
        return 0;
    }

    /* Just return something other than 0 */
    return -1;
}

inline DceRpcBoFlag DceRpcByteOrder(const uint8_t value)
{
    if ((value & 0x10) >> 4)
        return DCERPC_BO_FLAG__LITTLE_ENDIAN;

    return DCERPC_BO_FLAG__BIG_ENDIAN;
}

inline uint16_t DceRpcNtohs(const uint16_t* ptr, const DceRpcBoFlag bo_flag)
{
    uint16_t value;

    if (ptr == nullptr)
        return 0;

    value = *ptr;

    if (bo_flag == DCERPC_BO_FLAG__NONE)
        return value;

#ifdef WORDS_BIGENDIAN
    if (bo_flag == DCERPC_BO_FLAG__BIG_ENDIAN)
#else
    if (bo_flag == DCERPC_BO_FLAG__LITTLE_ENDIAN)
#endif  /* WORDS_BIGENDIAN */
        return value;

    return ((value & 0xff00) >> 8) | ((value & 0x00ff) << 8);
}

inline uint16_t DceRpcHtons(const uint16_t* ptr, const DceRpcBoFlag bo_flag)
{
    return DceRpcNtohs(ptr, bo_flag);
}

inline uint32_t DceRpcNtohl(const uint32_t* ptr, const DceRpcBoFlag bo_flag)
{
    uint32_t value;

    if (ptr == nullptr)
        return 0;

    value = *ptr;

    if (bo_flag == DCERPC_BO_FLAG__NONE)
        return value;

#ifdef WORDS_BIGENDIAN
    if (bo_flag == DCERPC_BO_FLAG__BIG_ENDIAN)
#else
    if (bo_flag == DCERPC_BO_FLAG__LITTLE_ENDIAN)
#endif  /* WORDS_BIGENDIAN */
        return value;

    return ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) |
           ((value & 0x0000ff00) << 8)  | ((value & 0x000000ff) << 24);
}

inline uint32_t DceRpcHtonl(const uint32_t* ptr, const DceRpcBoFlag bo_flag)
{
    return DceRpcNtohl(ptr, bo_flag);
}

inline uint64_t DceRpcNtohl64(const uint64_t* ptr, const DceRpcBoFlag bo_flag)
{
    uint64_t value;

    if (ptr == nullptr)
        return 0;

    value = *ptr;

    if (bo_flag == DCERPC_BO_FLAG__NONE)
        return value;

#ifdef WORDS_BIGENDIAN
    if (bo_flag == DCERPC_BO_FLAG__BIG_ENDIAN)
#else
    if (bo_flag == DCERPC_BO_FLAG__LITTLE_ENDIAN)
#endif  /* WORDS_BIGENDIAN */
        return value;

    return ((value & 0xff00000000000000) >> 56) | ((value & 0x00ff000000000000) >> 40) |
           ((value & 0x0000ff0000000000) >> 24) | ((value & 0x000000ff00000000) >> 8) |
           ((value & 0x00000000000000ff) << 56) | ((value & 0x000000000000ff00) << 40) |
           ((value & 0x0000000000ff0000) << 24) | ((value & 0x00000000ff000000) << 8);
}

inline uint64_t DceRpcHtonl64(const uint64_t* ptr, const DceRpcBoFlag bo_flag)
{
    return DceRpcNtohl64(ptr, bo_flag);
}

inline void DCE2_CopyUuid(Uuid* dst_uuid, const Uuid* pkt_uuid, const DceRpcBoFlag byte_order)
{
    dst_uuid->time_low = DceRpcNtohl(&pkt_uuid->time_low, byte_order);
    dst_uuid->time_mid = DceRpcNtohs(&pkt_uuid->time_mid, byte_order);
    dst_uuid->time_high_and_version = DceRpcNtohs(&pkt_uuid->time_high_and_version, byte_order);
    dst_uuid->clock_seq_and_reserved = pkt_uuid->clock_seq_and_reserved;
    dst_uuid->clock_seq_low = pkt_uuid->clock_seq_low;
    memcpy(dst_uuid->node, pkt_uuid->node, sizeof(dst_uuid->node));
}

inline int DCE2_BufferIsEmpty(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return 1;
    if ((buf->data == nullptr) || (buf->len == 0))
        return 1;
    return 0;
}

inline uint32_t DCE2_BufferLength(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return 0;
    return buf->len;
}

inline uint32_t DCE2_BufferSize(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return 0;
    return buf->size;
}

inline uint8_t* DCE2_BufferData(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return nullptr;
    return buf->data;
}

inline void DCE2_BufferEmpty(DCE2_Buffer* buf)
{
    if (buf == nullptr)
        return;
    buf->len = 0;
}

inline void dce2_move(const uint8_t*& data_ptr, uint16_t& data_len, int amount)
{
    data_len -= amount;
    data_ptr += amount;
}

inline void dce2_move(const uint8_t*& data_ptr, uint32_t& data_len, int amount)
{
    data_len -= amount;
    data_ptr += amount;
}

inline void dce2_move(const uint8_t*& data_ptr, int64_t& data_len, int amount)
{
    data_len -= amount;
    data_ptr += amount;
}

#endif
