//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

// circular_buffer.h author Hui Cao <huica@cisco.com>

#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

//  Circular buffer is thread safe for one writer and one reader thread
//  This implementation is inspired by one slot open approach.
//  See http://en.wikipedia.org/wiki/Circular_buffer

#include "main/snort_types.h"

#define CB_SUCCESS    0  // FIXIT-L use bool
#define CB_FAIL      (-1)

// Opaque buffer element type.  This would be defined by the application.
typedef void* ElemType;

struct _CircularBuffer;
typedef struct _CircularBuffer CircularBuffer;

// Initialize buffer based on number of elements
CircularBuffer* cbuffer_init(uint64_t size);

void cbuffer_free(CircularBuffer* cb);

int cbuffer_is_full(CircularBuffer* cb); // FIXIT-L use bool
int cbuffer_is_empty(CircularBuffer* cb); // FIXIT-L use bool

// Returns number of elements in use
uint64_t cbuffer_used(CircularBuffer* cb);

// Returns total number of elements
uint64_t cbuffer_size(CircularBuffer* cb);

// Returns CB_SUCCESS or CB_FAIL
int cbuffer_write(CircularBuffer* cb, const ElemType elem);

// Read one element from the buffer and remove it from buffer
// Returns CB_SUCCESS or CB_FAIL
int cbuffer_read(CircularBuffer* cb, ElemType* elem);

#endif

