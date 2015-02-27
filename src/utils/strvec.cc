//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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
// strvec.cc author Russ Combs <rcombs@sourcefire.com>

#include <stdlib.h>

#include "strvec.h"
#include "util.h"

typedef struct
{
    char** v;
    unsigned n;
} StringVector;

void* StringVector_New(void)
{
    StringVector* sv = (StringVector*)SnortAlloc(sizeof(*sv));
    sv->v = (char**)SnortAlloc(sizeof(*sv->v));
    sv->n = 0;
    return sv;
}

void StringVector_Delete(void* pv)
{
    unsigned i;
    StringVector* sv = (StringVector*)pv;

    if ( !sv )
        return;

    for ( i = 0; i < sv->n; i++ )
        free(sv->v[i]);

    free(sv->v);
    free(sv);
}

int StringVector_Add(void* pv, const char* s)
{
    StringVector* sv = (StringVector*)pv;
    char** v;

    if ( !sv || !s )
        return 0;

    v = (char**)realloc(sv->v, (sv->n+2) * sizeof(char*));

    if ( !v )
        return 0;

    sv->v = v;
    sv->v[sv->n++] = SnortStrdup(s);
    sv->v[sv->n] = NULL;

    return 1;
}

char* StringVector_Get(void* pv, unsigned index)
{
    StringVector* sv = (StringVector*)pv;

    if ( !sv || index >= sv->n )
        return NULL;

    return sv->v[index];
}

int StringVector_AddVector(void* pd, void* ps)
{
    unsigned i = 0;
    const char* s = StringVector_Get(ps, i++);

    while ( s )
    {
        if ( !StringVector_Add(pd, s) )
            return 0;

        s = StringVector_Get(ps, i++);
    }
    return 1;
}

const char** StringVector_GetVector(void* pv)
{
    StringVector* sv = (StringVector*)pv;

    if ( !sv )
        return NULL;

    return (const char**)sv->v;
}

