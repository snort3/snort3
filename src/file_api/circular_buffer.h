//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
/*
 **  Circular buffer is thread safe for one writer and one reader thread
 **
 **  This implementation is inspired by one slot open approach.
 **  See http://en.wikipedia.org/wiki/Circular_buffer
 **
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.25.13 - Initial Source Code. Hui Cao
 */

#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

#define CB_SUCCESS   0
#define CB_FAIL      -1

/* Opaque buffer element type.  This would be defined by the application. */
typedef void* ElemType;

struct _CircularBuffer;
typedef struct _CircularBuffer CircularBuffer;

/*
 * Initialize buffer based on number of elements
 *
 * Args:
 *   uint64_t size: number of elements *
 * Return:
 *   CircularBuffer *: pointer to the buffer
 *   NULL: failed
 *
 */
CircularBuffer* cbuffer_init(uint64_t size);

/* Release all memory used*/
void cbuffer_free(CircularBuffer* cb);

/*
 * Check whether buffer is full
 *
 * Return:
 *   1: full
 *   0: not full
 */
int cbuffer_is_full(CircularBuffer* cb);

/*
 * Check whether buffer is empty
 *
 * Return:
 *   1: empty
 *   0: not empty
 */
int cbuffer_is_empty(CircularBuffer* cb);

/* Returns number of elements in use*/
uint64_t cbuffer_used(CircularBuffer* cb);

/* Returns number of free elements*/
uint64_t cbuffer_available(CircularBuffer* cb);

/* Returns total number of elements*/
uint64_t cbuffer_size(CircularBuffer* cb);

/*
 * Add one element to the buffer
 *
 * Args:
 *   CircularBuffer *: buffer
 *   ElemType elem: the element to be added
 * Return:
 *   CB_FAIL
 *   CB_SUCCESS
 */
int cbuffer_write(CircularBuffer* cb, const ElemType elem);

/*
 * Read one element from the buffer and remove it from buffer
 *
 * Args:
 *   CircularBuffer *: buffer
 *   ElemType *elem: the element pointer to be stored
 * Return:
 *   CB_FAIL
 *   CB_SUCCESS
 */
int cbuffer_read(CircularBuffer* cb, ElemType* elem);

/*
 * Read one element from the buffer and no change on buffer
 *
 * Args:
 *   CircularBuffer *: buffer
 *   ElemType *elem: the element pointer to be stored
 * Return:
 *   CB_FAIL
 *   CB_SUCCESS
 */

int cbuffer_peek(CircularBuffer* cb, ElemType* elem);

/* Returns total number of reads*/
uint64_t cbuffer_num_reads(CircularBuffer* cb);

/* Returns total number of writes*/
uint64_t cbuffer_num_writes(CircularBuffer* cb);

/* Returns total number of writer overruns*/
uint64_t cbuffer_num_over_runs(CircularBuffer* cb);

/* Returns total number of reader overruns*/
uint64_t cbuffer_num_under_runs(CircularBuffer* cb);

#endif

