//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

/*
  sfmemcap.c

  These functions wrap the alloc & free functions. They enforce a memory cap using
  the MEMCAP structure.  The MEMCAP structure tracks memory usage.  Each allocation
  has 4 bytes added to it so we can store the allocation size.  This allows us to
  free a block and accurately track how much memory was recovered.

  Marc Norton
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfmemcap.h"

#include "util.h"
#include "util_cstring.h"

/*
*   Set max # bytes & init other variables.
*/
void sfmemcap_init(MEMCAP* mc, unsigned long nbytes)
{
    mc->memcap = nbytes;
    mc->memused= 0;
    mc->nblocks= 0;
}

/*
*  Allocate some memory
*/
void* sfmemcap_alloc(MEMCAP* mc, unsigned long nbytes)
{
    long* data;

    //printf("sfmemcap_alloc: %d bytes requested, memcap=%d,
    // used=%d\n",nbytes,mc->memcap,mc->memused);

    nbytes += sizeof(long);

    /* Check if we are limiting memory use */
    if ( mc->memcap > 0 )
    {
        /* Check if we've maxed out our memory - if we are tracking memory */
        if ( (mc->memused + nbytes) > mc->memcap )
        {
            return nullptr;
        }
    }

    //data = (long*)snort_alloc( nbytes );
    data = (long*)snort_calloc(nbytes);
    *data++ = (long)nbytes;

    mc->memused += nbytes;
    mc->nblocks++;

    return data;
}

/*
*   Free some memory
*/
void sfmemcap_free(MEMCAP* mc, void* p)
{
    long* q;

    q = (long*)p;
    q--;
    mc->memused -= (unsigned)(*q);
    mc->nblocks--;

    snort_free(q);
}

/*
*   For debugging.
*/
void sfmemcap_showmem(MEMCAP* mc)
{
    fprintf(stderr, "memcap: memcap = %lu bytes,",mc->memcap);
    fprintf(stderr, " memused= %lu bytes,",mc->memused);
    fprintf(stderr, " nblocks= %d blocks\n",mc->nblocks);
}

