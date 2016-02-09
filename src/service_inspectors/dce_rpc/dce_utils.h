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

#ifndef _DCE_UTILS_H_
#define _DCE_UTILS_H_

#include <string.h>
#include <ctype.h>
#include "main/snort_types.h"
#include "utils/snort_bounds.h"

/********************************************************************
 * Macros
 ********************************************************************/
#define DCE2_SENTINEL -1
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

/********************************************************************
 * Inline function prototypes
 ********************************************************************/

static inline bool DCE2_IsSpaceChar(const char);
static inline bool DCE2_IsConfigEndChar(const char);

static inline char* DCE2_PruneWhiteSpace(char*);
static inline bool DCE2_IsEmptyStr(char*);

static inline int DCE2_UuidCompare(const void*, const void*);

/********************************************************************
 * Public function prototypes
 ********************************************************************/
DCE2_Ret DCE2_GetValue(char*, char*, void*, int, DCE2_IntType, uint8_t);

/********************************************************************
 * Function: DCE2_IsSpaceChar()
 *
 * Determines if the character passed in is a character that
 * the preprocessor considers a to be a space character.
 *
 * Arguments:
 *  const char
 *      The character to make the determination on.
 *
 * Returns:
 *  bool
 *      true if a valid space character.
 *      false if not a valid space character.
 *
 ********************************************************************/
static inline bool DCE2_IsSpaceChar(const char c)
{
    if (isspace((int)c))
        return true;
    return false;
}

/********************************************************************
 * Function: DCE2_IsConfigEndChar()
 *
 * Determines if the character passed in is a character that
 * the preprocessor considers a to be an end of configuration
 * character.
 *
 * Arguments:
 *  const char
 *      The character to make the determination on.
 *
 * Returns:
 *  bool
 *      true if a valid end of configuration character.
 *      false if not a valid end of configuration character.
 *
 ********************************************************************/
static inline bool DCE2_IsConfigEndChar(const char c)
{
    if (c == DCE2_CFG_TOK__END)
        return true;
    return false;
}

/********************************************************************
 * Function: DCE2_PruneWhiteSpace()
 *
 * Prunes whitespace surrounding string.
 * String must be 0 terminated.
 *
 * Arguments:
 *  char *
 *      NULL terminated string to prune.
 *  int
 *      length of string
 *
 * Returns:
 *  char * - Pointer to the pruned string.  Note that the pointer
 *           still points within the original string.
 *
 * Side effects: Spaces at the end of the string passed in as an
 *               argument are replaced by NULL bytes.
 *
 ********************************************************************/
static inline char* DCE2_PruneWhiteSpace(char* str)
{
    char* end;

    if (str == nullptr)
        return nullptr;

    /* Put end a char before NULL byte */
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

/********************************************************************
 * Function: DCE2_IsEmptyStr()
 *
 * Checks if string is NULL, empty or just spaces.
 * String must be 0 terminated.
 *
 * Arguments: None
 *  char * - string to check
 *
 * Returns:
 *  true  if string is NULL, empty or just spaces
 *  false  otherwise
 *
 ********************************************************************/
static inline bool DCE2_IsEmptyStr(char* str)
{
    char* end;

    if (str == nullptr)
        return 1;

    end = str + strlen(str);

    while ((str < end) && isspace((int)*str))
        str++;

    if (str == end)
        return true;

    return false;
}

static inline int DCE2_UuidCompare(const void* data1, const void* data2)
{
    const Uuid* uuid1 = (Uuid*)data1;
    const Uuid* uuid2 = (Uuid*)data2;

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

#endif  /* _DCE2_UTILS_H_ */

