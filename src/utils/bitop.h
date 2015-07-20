//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// bitop.h authors Dan Roelker <droelker@sourcefire.com>
//     and Marc Norton <mnorton@sourcefire.com>

#ifndef BITOP_H
#define BITOP_H

// A poor man's bit vector implementation

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "main/snort_debug.h"

// FIXIT-L replace this with a dynamic bitset or some such
// at least reimplement into a reasonable class

struct _BITOP
{
    unsigned char* pucBitBuffer;
    unsigned int uiBitBufferSize;
    unsigned int uiMaxBits;
};

using BITOP = struct _BITOP;

// Initialize the BITOP struct.
// Use this if you handle the bitop buffer allocation yourself.
// You must zero the buffer yourself before use.
// returns 0 if successful, 1 otherwise
// FIXIT-L: Change return type to bool
// FIXIT-L: Change int len -> size_t len
static inline int boInitStaticBITOP(BITOP* BitOp, int len, unsigned char* buf)
{
    if ( len < 1 || !buf || !BitOp )
        return 1;

    BitOp->pucBitBuffer    = buf;
    BitOp->uiBitBufferSize = (unsigned int)len;
    BitOp->uiMaxBits       = (unsigned int)(len << 3);

    return 0;
}

// Initializes the BITOP structure for use.
// returns 0 if successful, 1 otherwise
// FIXIT-L: Change return type to bool
// FIXIT-L: Change int len -> size_t len
static inline int boInitBITOP(BITOP* BitOp, int len)
{
    if ( len < 1 || !BitOp )
        return 1;

    // Check for already initialized buffer
    if ( BitOp->pucBitBuffer )
        return 0;

    BitOp->pucBitBuffer = (unsigned char*)calloc(1, len);
    if ( !BitOp->pucBitBuffer )
        return 1;

    BitOp->uiBitBufferSize = (unsigned int)len;
    BitOp->uiMaxBits       = (unsigned int)(len << 3);

    return 0;
}

// Reset the bit buffer so that it can be reused
// returns 0 if successful, 1 otherwise
// FIXIT-L: Change return type to bool
static inline int boResetBITOP(BITOP* BitOp)
{
    if ( !BitOp )
        return 1;

    memset(BitOp->pucBitBuffer, 0, BitOp->uiBitBufferSize);
    return 0;
}

// Reset the bit buffer to all 1's so that it can be reused
// returns 0 if successful, 1 otherwise
// FIXIT-L: Change return type to bool
static inline int boSetAllBits(BITOP* BitOp)
{
    if ( !BitOp )
        return 1;

    memset(BitOp->pucBitBuffer, 0xff, BitOp->uiBitBufferSize);
    return 0;
}

// Set the bit in the specified position within the bit buffer.
// returns 0 if successful, 1 otherwise
// FIXIT-L: Change return type to bool
static inline int boSetBit(BITOP* BitOp, unsigned int bit)
{
    if ( !BitOp || BitOp->uiMaxBits <= bit )
        return 1;

    unsigned char mask = (unsigned char)(0x80 >> (bit & 7));

    BitOp->pucBitBuffer[bit >> 3] |= mask;

    return 0;
}

// Checks if the bit at the specified position is set
// returns 0 if bit not set, 1 if bit is set.
// FIXIT-L: Change return type to bool
static inline int boIsBitSet(BITOP* BitOp, unsigned int bit)
{
    if ( !BitOp || BitOp->uiMaxBits <= bit )
        return 0;

    unsigned char mask = (unsigned char)(0x80 >> (bit & 7));

    return mask & BitOp->pucBitBuffer[bit >> 3];
}

// Clear the bit in the specified position within the bit buffer.
static inline void boClearBit(BITOP* BitOp, unsigned int bit)
{
    if ( !BitOp || BitOp->uiMaxBits <= bit )
        return;

    unsigned char mask = (unsigned char)(0x80 >> (bit & 7));
    BitOp->pucBitBuffer[bit >> 3] &= ~mask;
}

// Clear the byte in the specified position within the bit buffer.
static inline void boClearByte(BITOP* BitOp, unsigned int pos)
{
    if ( BitOp && BitOp->uiMaxBits > pos )
        BitOp->pucBitBuffer[pos >> 3] = 0;
}

// Frees memory created by boInitBITOP
// Only use this function if you used boInitBITOP to create the buffer!
static inline void boFreeBITOP(BITOP* BitOp)
{
    if ( !BitOp || !BitOp->pucBitBuffer )
        return;

    free(BitOp->pucBitBuffer);
    BitOp->pucBitBuffer = nullptr;
}

#endif

