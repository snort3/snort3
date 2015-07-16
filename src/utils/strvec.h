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
// strvec.h author Russ Combs <rcombs@sourcefire.com>

#ifndef STRVEC_H
#define STRVEC_H

// Vanilla string vector implementation
// FIXIT-L: Replace with an STL vector?

void* StringVector_New(void);
void StringVector_Delete(void*);

int StringVector_Add(void*, const char*);
char* StringVector_Get(void*, unsigned index);

int StringVector_AddVector(void* dst, void* src);
const char** StringVector_GetVector(void*);

#endif

