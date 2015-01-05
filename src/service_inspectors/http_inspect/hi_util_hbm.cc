/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2003-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/**
**  @file       hi_hbm.c
**
**  @author     Marc Norton <mnorton@sourcefire.com>
**
**  @brief      Implementation of a Horspool method of Boyer-Moore
**
*/

#include "hi_util_hbm.h"
#include <stdlib.h>
#include "util.h"

/*
*  Boyer-Moore-Horspool for small pattern groups
*/
int hbm_prepx(HBM_STRUCT *p, unsigned char * pat, int m)
{
     int     k;

     if( !m ) return 0;
     if( !p ) return 0;


     p->P = pat;

     p->M = m;

     /* Compute normal Boyer-Moore Bad Character Shift */
     for(k = 0; k < 256; k++) p->bcShift[k] = m;
     for(k = 0; k < m; k++)   p->bcShift[pat[k]] = m - k - 1;

     return 1;
}

HBM_STRUCT * hbm_prep(unsigned char * pat, int m)
{
     HBM_STRUCT    *p;

     p = (HBM_STRUCT*)SnortAlloc(sizeof(HBM_STRUCT));

     if( !hbm_prepx( p, pat, m ) )
     {
          FatalError("Error initializing pattern matching. Check arguments.");
     }

     return p;
}

/*
*   Boyer-Moore Horspool
*   Does NOT use Sentinel Byte(s)
*   Scan and Match Loops are unrolled and separated
*   Optimized for 1 byte patterns as well
*/
unsigned char * hbm_match(HBM_STRUCT * px, unsigned char *text, int n)
{
  unsigned char *pat, *t, *et, *q;
  int            m1, k;
  short    *bcShift;

  m1     = px->M-1;
  pat    = px->P;
  bcShift= px->bcShift;

  t  = text + m1;
  et = text + n;

  /* Handle 1 Byte patterns - it's a faster loop */
  /*
  if( !m1 )
  {
    for( ;t<et; t++ )
      if( *t == *pat ) return t;
    return 0;
  }
  */

  /* Handle MultiByte Patterns */
  while( t < et )
  {
    /* Scan Loop - Bad Character Shift */
    do
    {
      t += bcShift[*t];
      if( t >= et )return 0;;

      t += (k=bcShift[*t]);
      if( t >= et )return 0;

    } while( k );

    /* Unrolled Match Loop */
    k = m1;
    q = t - m1;
    while( k >= 4 )
    {
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
    }
    /* Finish Match Loop */
    while( k >= 0 )
    {
      if( pat[k] != q[k] )goto NoMatch;  k--;
    }
    /* If matched - return 1st char of pattern in text */
    return q;

NoMatch:

    /* Shift by 1, this replaces the good suffix shift */
    t++;
  }

  return 0;
}

