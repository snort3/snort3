//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SFMEMCAP_H
#define SFMEMCAP_H

// _alloc and _free wrappers that enforce a memory cap

struct MEMCAP
{
    unsigned long memused;
    unsigned long memcap;
    int nblocks;
};

// FIXIT-L could be refactored as a class but should be deleted
void sfmemcap_init(MEMCAP* mc, unsigned long nbytes);
MEMCAP* sfmemcap_new(unsigned nbytes);
void sfmemcap_delete(MEMCAP* mc);
void* sfmemcap_alloc(MEMCAP* mc, unsigned long nbytes);
void sfmemcap_showmem(MEMCAP* mc);
void sfmemcap_free(MEMCAP* mc, void* memory);
char* sfmemcap_SnortStrdup(MEMCAP* mc, const char* str);
void* sfmemcap_dupmem(MEMCAP* mc, void* src, unsigned long n);

#endif

