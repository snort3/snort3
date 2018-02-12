//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// sip_utils.cc author: Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_utils.h"

#include <cstring>

#include "hash/hashfcn.h"

/*
 * Trim spaces non-destructively on both sides of string : '', \t, \n, \r
 * If string is empty return 0, otherwise 1
 * Note: end point to the location start + length,
 *       not necessary the real end of string if not end with \0
 */
int SIP_TrimSP(const char* start, const char* end, const char** new_start, const char** new_end)
{
    const char* before;
    const char* after;

    if (start >= end )
    {
        *new_start = start;
        *new_end = *new_start;
        return 0;
    }

    before = start;

    // Trim the starting spaces
    while ((before < end) && isspace((int)*before))
    {
        before++;
    }
    // This is an empty string
    if (before == end)
    {
        *new_start = end;
        *new_end = *new_start;
        return 0;
    }

    // Trim the ending spaces
    after = end - 1;
    while ((before < after) && isspace((int)*after))
    {
        after--;
    }
    *new_start = before;
    *new_end = after + 1;
    return 1;
}

/********************************************************************
 * Function: SIP_FindMethod()
 *
 * Find method in the method list by name
 *
 * Arguments:
 *  SIPMethodlist - methods list to be searched,
 *  char *        - method name,
 *  int           - length of the method name
 *
 * Returns:
 *  SIPMethodNode*- the founded method node, or NULL if not founded
 *
 ********************************************************************/

SIPMethodNode* SIP_FindMethod(SIPMethodlist methods, const char* methodName, unsigned int length)
{
    SIPMethodNode* method = methods;
    while (nullptr != method)
    {
        if ((length == strlen(method->methodName))&&
            (strncasecmp(method->methodName, methodName, length) == 0))
        {
            return method;
        }
        method = method->nextm;
    }
    return method;
}

/********************************************************************
 * Function: strToHash()
 *
 * Calculate the hash value of a string
 *
 * Arguments:
 *  char * - string to be hashed
 *  int: length of the string
 *
 * Returns:
 *  1  if string is NULL, empty or just spaces
 *  0  otherwise
 *
 ********************************************************************/
uint32_t strToHash(const char* str, int length)
{
    uint32_t a = 0, b = 0, c = 0;
    int i,j;

    for (i=0,j=0; i<length; i+=4)
    {
        uint32_t tmp = 0;
        int k = length - i;

        if (k > 4)
            k=4;

        for (int l=0; l<k; l++)
        {
            tmp |= *(str + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }
    finalize(a,b,c);
    return c;
}

