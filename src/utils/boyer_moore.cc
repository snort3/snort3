//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

// boyer_moore.cc was split out of mstring.cc which had these comments:

/***************************************************************************
 *
 * File: MSTRING.C
 *
 * Purpose: Provide a variety of string functions not included in libc.  Makes
 *          up for the fact that the libstdc++ is hard to get reference
 *          material on and I don't want to write any more non-portable c++
 *          code until I have solid references and libraries to use.
 *
 * History:
 *
 * Date:      Author:  Notes:
 * ---------- ------- ----------------------------------------------
 *  08/19/98    MFR    Initial coding begun
 *  03/06/99    MFR    Added Boyer-Moore pattern match routine
 *  12/31/99	JGW    Added a full Boyer-Moore implementation to increase
 *                     performance. Added a case insensitive version of mSearch
 *  07/24/01    MFR    Fixed Regex pattern matcher introduced by Fyodor
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "boyer_moore.h"

#include "util.h"

namespace snort
{
/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int* make_skip(const char* ptrn, int plen)
{
    int i;
    int* skip = (int*)snort_calloc(256, sizeof(int));

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while (plen != 0)
        skip[(unsigned char)*ptrn++] = plen--;

    return skip;
}

/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int* make_shift(const char* ptrn, int plen)
{
    int* shift = (int*)snort_calloc(plen, sizeof(int));
    int* sptr = shift + plen - 1;
    const char* pptr = ptrn + plen - 1;
    char c;

    c = ptrn[plen - 1];

    *sptr = 1;

    while (sptr-- != shift)
    {
        const char* p1 = ptrn + plen - 2, * p2, * p3;

        do
        {
            while (p1 >= ptrn && *p1-- != c)
                ;

            p2 = ptrn + plen - 2;
            p3 = p1;

            while (p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr)
                ;
        }
        while (p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}

/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      -1 if not found or offset >= 0 if found
 *
 ****************************************************************/
int mSearch(
    const char* buf, int blen, const char* ptrn, int plen, const int* skip, const int* shift)
{
    if (plen == 0)
        return -1;

    int b_idx = plen;

    while (b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while (buf[--b_idx] == ptrn[--p_idx])
        {
            if (p_idx == 0)
                return b_idx;
        }

        skip_stride = skip[(unsigned char)buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return -1;
}

/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      -1 if not found or offset >= 0 if found
 *
 ****************************************************************/
int mSearchCI(
    const char* buf, int blen, const char* ptrn, int plen, const int* skip, const int* shift)
{
    int b_idx = plen;

    if (plen == 0)
        return -1;

    while (b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while ((unsigned char)ptrn[--p_idx] == toupper((unsigned char)buf[--b_idx]))
        {
            if (p_idx == 0)
                return b_idx;
        }

        skip_stride = skip[toupper((unsigned char)buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return -1;
}
}
