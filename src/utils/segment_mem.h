//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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
// segment_mem.h author Hui Cao <huica@cisco.com>

#ifndef SEGMENT_MEM_H
#define SEGMENT_MEM_H

// Segment memory allocation used by sfrt

#include <cstddef>
#include <cstdint>

using MEM_OFFSET = uint32_t;

int segment_meminit(uint8_t*, size_t);
MEM_OFFSET segment_snort_alloc(size_t size);
void segment_free(MEM_OFFSET ptr);
MEM_OFFSET segment_snort_calloc(size_t num, size_t size);
size_t segment_unusedmem();
void* segment_basePtr();

#endif

