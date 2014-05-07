/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
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

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      ScratchPad class declaration
//

#ifndef NHTTP_SCRATCHPAD_H
#define NHTTP_SCRATCHPAD_H


//-------------------------------------------------------------------------
// ScratchPad class
// Memory management for NHttpMsgHeader class
//-------------------------------------------------------------------------

// Working space and storage for all the derived fields
// Return value of request is 32-bit aligned and may be freely cast to uint32_t*
// 1. request the maximum number of bytes you might need
// 2. use what you need
// 3. commit() what you actually used if you want to keep it
// Anything you do not commit will be reused by the next request.

class ScratchPad {
public:
    ScratchPad(uint32_t *buff, uint32_t length) : buffer(buff), capacity(length*4), used(0) {}; // Careful: length must be number of uint32_ts provided, not octets.
    void reinit() {used = 0;};
    uint8_t *request(uint32_t needed) const {return (needed <= capacity-used) ? (uint8_t*)(buffer+used) : nullptr;};
    void commit(uint32_t taken) { used += taken + (4-(taken%4))%4; };  // round up to multiple of 4 to preserve alignment

private:
    uint32_t *buffer;
    uint32_t capacity;
    uint32_t used;
};

#endif

