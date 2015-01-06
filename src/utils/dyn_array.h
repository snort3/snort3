//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DYN_ARRAY_H
#define DYN_ARRAY_H

/* Dynamic array bound checks:
 * If index is greater than maxElement then realloc like operation is performed.
 *
 * @param dynArray - dynamic array
 *
 * @param index - 0 based. Index of element that will be accessed by application
 *    either as rvalue or lvalue.
 *
 * @param maxElements - Number of elements already allocated in dynArray.
 *     0 value means no elements are allocated
 *     and therefore dynArray[0] will cause memory allocation.
 */
int sfDynArrayCheckBounds (
    void** dynArray, unsigned int index, unsigned int *maxElements);

#endif

