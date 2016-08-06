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

/**
**  @file       hi_util.h
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      HttpInspect utility functions.
**
**  Contains function prototype and inline utility functions.
**
**  NOTES:
**      - Initial development.  DJR
*/

#ifndef HI_UTIL_H
#define HI_UTIL_H

#include "hi_include.h"

/*
**  This function checks for in bounds condition on buffers.
**
**  This is very important for much of what we do here, since inspecting
**  data buffers is mainly what we do.  So we always make sure that we are
**  within the buffer.
**
**  This checks a half-open interval with the end pointer being one char
**  after the end of the buffer.
**
**  @retval 1 within bounds
**  @retval 0 not within bounds
*/
inline int hi_util_in_bounds(const u_char* start, const u_char* end, const u_char* p)
{
    if (p >= start && p < end)
    {
        return 1;
    }

    return 0;
}

inline void SkipWhiteSpace(const u_char* start, const u_char* end,
    const u_char** ptr)
{
    while (hi_util_in_bounds(start, end, *ptr) && isspace((int)**ptr) && (**ptr != '\n'))
        (*ptr)++;
}

inline int SkipBlankSpace(const u_char* start, const u_char* end,
    const u_char** ptr)
{
    int count = 0;
    while ((hi_util_in_bounds(start, end, *ptr)) && ( **ptr == ' ' || **ptr == '\t') )
    {
        (*ptr)++;
        count++;
    }
    return count;
}

inline void SkipDigits(const u_char* start, const u_char* end,
    const u_char** ptr)
{
    while ((hi_util_in_bounds(start, end, *ptr)) && (isdigit((int)**ptr)) )
    {
        (*ptr)++;
    }
}

inline void SkipBlankAndNewLine(const u_char* start, const u_char* end,
    const u_char** ptr)
{
    while ( (hi_util_in_bounds(start, end, *ptr)) &&
        ( **ptr == ' ' || **ptr == '\t') && (**ptr != '\n')  )
    {
        (*ptr)++;
    }
}

inline void SkipCRLF(const u_char* start, const u_char* end,
    const u_char** ptr)
{
    while ( (hi_util_in_bounds(start, end, *ptr)) &&
        ( **ptr == '\r' || **ptr == '\n') )
    {
        (*ptr)++;
    }
}

inline int IsHeaderFieldName(const u_char* p, const u_char* end,
    const char* header_name, size_t header_len)
{
    if ((p+header_len) <= end)
    {
        if (!strncasecmp((const char*)p, header_name, header_len))
            return 1;
        else
            return 0;
    }
    return 0;
}

#endif  /* HI_UTIL_H */

