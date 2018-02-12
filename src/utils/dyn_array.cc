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

#include "dyn_array.h"

#include "util.h"

// number of additional policies allocated with each re-alloc operation
#define POLICY_ALLOCATION_CHUNK 10

int sfDynArrayCheckBounds(  // FIXIT-L replace with vector
    void** dynArray,
    unsigned int index,
    unsigned int* maxElements
    )
{
    void* ppTmp = nullptr;

    if (index >= *maxElements)
    {
        //expand the array
        ppTmp = snort_calloc(index+POLICY_ALLOCATION_CHUNK, sizeof(void*));

        if (*maxElements)
        {
            memcpy(ppTmp, *dynArray, sizeof(void*)*(*maxElements));
            snort_free(*dynArray);
        }

        *dynArray = ppTmp;
        *maxElements = index + POLICY_ALLOCATION_CHUNK;
    }

    return 0;
}

