//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "dyn_array.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "main/snort_debug.h"
#include "sfrt/sfrt.h"

/**Number of additional policies allocated with each re-alloc operation. */
#define POLICY_ALLOCATION_CHUNK 10

// FIXIT-L replace with vector
int sfDynArrayCheckBounds(
    void** dynArray,
    unsigned int index,
    unsigned int* maxElements
    )
{
    void* ppTmp = NULL;

    if (index >= *maxElements)
    {
        //expand the array
        ppTmp = calloc(index+POLICY_ALLOCATION_CHUNK, sizeof(void*));
        if (!(ppTmp))
        {
            return -1;
        }

        if (*maxElements)
        {
            memcpy(ppTmp, *dynArray, sizeof(void*)*(*maxElements));
            free(*dynArray);
        }

        *dynArray = ppTmp;
        *maxElements = index + POLICY_ALLOCATION_CHUNK;
    }

    return 0;
}

