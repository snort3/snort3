//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_scratch_pad.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_SCRATCH_PAD_H
#define NHTTP_SCRATCH_PAD_H

//-------------------------------------------------------------------------
// ScratchPad class
// Storage management class
//-------------------------------------------------------------------------

// Working space and storage for all the derived fields
// Return value of request is 64-bit aligned and may be freely cast to uint64_t*
// 1. request the maximum number of bytes you might need
// 2. use what you need
// 3. commit() what you actually used if you want to keep it
// Anything you do not commit will be reused by the next request.

class ScratchPad
{
public:
    ScratchPad(uint32_t _capacity) : capacity(_capacity), buffer(new uint64_t[_capacity/8+1]) { }
    ~ScratchPad() { delete[] buffer; }
    uint8_t* request(uint32_t needed) const
    {
        return (needed <= capacity-used) ?
               ((uint8_t*)buffer)+used : nullptr;
    }
    // round up to multiple of 8 for alignment
    void commit(uint32_t taken) { used += taken + (8-(taken%8))%8; }

private:
    const uint32_t capacity;
    uint64_t* const buffer;
    uint32_t used = 0;
};

#endif

