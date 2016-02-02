//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

/*
*  snprintf that appends to destination buffer
*
*  Author: Steven Sturges
*/
#include "sfsnprintfappend.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include "util.h"

/****************************************************************************
 *
 * Function: sfsnprintfappend
 *
 * Purpose: snprintf that appends to destination buffer
 *
 *          Appends the snprintf format string and arguments to dest
 *          without going beyond dsize bounds.  Assumes dest has
 *          been properly allocated, and is of dsize in length.
 *
 * Arguments: dest      ==> pointer to string buffer to append to
 *            dsize     ==> size of buffer dest
 *            format    ==> snprintf format string
 *            ...       ==> arguments for printf
 *
 * Returns: number of characters added to the buffer
 *
 ****************************************************************************/
int sfsnprintfappend(char* dest, int dsize, const char* format, ...)
{
    int currLen, appendLen;
    va_list ap;

    if (!dest || dsize == 0)
        return -1;

    currLen = SnortStrnlen(dest, dsize);
    if (currLen == -1)
        return -1;

    va_start(ap, format);
    appendLen = vsnprintf(dest+currLen, dsize-currLen, format, ap);
    va_end(ap);

    dest[dsize-1]=0; /* guarantee a null tremination */

    return appendLen;
}

