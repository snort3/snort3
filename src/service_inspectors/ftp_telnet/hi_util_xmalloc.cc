/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

/*
**  util.c
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include "main/thread.h"

//#define MDEBUG

static THREAD_LOCAL unsigned msize=0;

void * xmalloc(size_t byteSize) // FIXIT-L eliminate this nonsense
{
#ifdef MDEBUG
   int * data = (int*) malloc( byteSize + 4 );
   unsigned m = msize;

   if(data)memset(data,0,byteSize+4);
#else
   int * data = (int*) malloc( byteSize );
   if(data)memset(data,0,byteSize);
#endif

   if( data == NULL )
    {
        return NULL;
    }

#ifdef MDEBUG

	msize += byteSize + 4;

	*data = byteSize+4;

    //printf("** xmalloc msize=%u, allocbytes=%d, msize=%u  %x\n", m, byteSize+4, msize, data);

	data++;

    return data;

#else

	msize += byteSize;

    return data;
#endif
}

void xfree( void * p )
{
#ifdef MDEBUG
   unsigned m = msize;
   int  *q = (int*)p;
   q--;
   msize -= *q;

   free(q);

#else

   free(p);

#endif


}

void xshowmem(void)
{
#ifdef MDEBUG
	  printf("xmalloc-mem: %u bytes\n",msize);
#endif
}

char *xstrdup(const char *str)
{
    int dsize;
	char *data = NULL;

    dsize = strlen(str) + 1;
    data = (char *)xmalloc(dsize);

	if(data == NULL)
    {
        return NULL;
    }

    strncpy(data, str, dsize - 1);
    data[dsize - 1] = '\0';

    return data;
}

