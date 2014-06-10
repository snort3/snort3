/*
**
** bitopt_funcs.h
**
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
** NOTES
**   5.15.02 - Initial Source Code. Norton/Roelker
**   5.23.02 - Moved bitop functions to bitop.h to inline. Norton/Roelker
**   1.21.04 - Added static initialization. Roelker
**   9.13.05 - Separated type and inline func definitions. Sturges
**
*/

#ifndef BITOP_FUNCS_H
#define BITOP_FUNCS_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_debug.h"
#include "utils/bitop.h"

/*
**  NAME
**    boInitStaticBITOP::
*/
/**
**  This function is for use if you handle the bitop buffer allocation
**  yourself.  Just pass in the char array and the number of bytes the array
**  is and this function sets up the structure for you.
**
**  @retval int
**
**  @return  0  successful
**  @return !0  failed
*/
static inline int boInitStaticBITOP(BITOP *BitOp,int iBytes,unsigned char *buf)
{
    if(iBytes < 1 || !buf || !BitOp)
        return 1;

    BitOp->pucBitBuffer   = buf;
    BitOp->uiBitBufferSize = (unsigned int)iBytes;
    BitOp->uiMaxBits       = (unsigned int)(iBytes << 3);

    memset(buf, 0x00, iBytes);

    return 0;
}

/*
**
**  NAME
**    boInitBITOP
**
**  DESCRIPTION
**    Initializes the BITOP structure for use.
**
**    NOTE:
**    BITOP structure must be zeroed to avoid misinterpretation
**    of initialization.
**
**  FORMAL INPUTS
**    BITOP * - the structure to initialize
**    int     - the number of bit positions to hold.
**
**  FORMAL OUTPUTS
**    int - 0 if successful, 1 if failed.
**
*/
static inline int boInitBITOP(BITOP *BitOp, int iBytes)
{
    int iSize;

    /*
    **  Sanity check for size
    */
    if((iBytes < 1) || (BitOp == NULL))
    {
        return 1;
    }

    /*
    **  Check for already initialized buffer, and
    **  if it is already initialized then we return that it
    **  is initialized.
    */
    if(BitOp->pucBitBuffer)
    {
        return 0;
    }

    iSize = iBytes << 3;

    BitOp->pucBitBuffer = (unsigned char  *)calloc(1, iBytes);
    if(BitOp->pucBitBuffer == NULL)
    {
        return 1;
    }

    BitOp->uiBitBufferSize = (unsigned int)iBytes;
    BitOp->uiMaxBits       = (unsigned int)iSize;

    return 0;
}

/*
**
**  NAME
**    boResetBITOP
**
**  DESCRIPTION
**    This resets the bit buffer so that it can be used again.
**
**  FORMAL INPUTS
**    BITOP * - structure to reset
**
**  FORMAL OUTPUT
**    int - 0 if successful, 1 if failed.
**
*/
static inline int boResetBITOP(BITOP *BitOp)
{
    if (BitOp == NULL)
        return 1;

    memset(BitOp->pucBitBuffer, 0x00, BitOp->uiBitBufferSize);
    return 0;
}

/*
**
**  NAME
**    boSetAllBits
**
**  DESCRIPTION
**    This resets the bit buffer to all 1's so that it can be used again.
**
**  FORMAL INPUTS
**    BITOP * - structure to reset
**
**  FORMAL OUTPUT
**    int - 0 if successful, 1 if failed.
**
*/
static inline int boSetAllBits(BITOP *BitOp)
{
    if (BitOp == NULL)
        return 1;

    memset(BitOp->pucBitBuffer, 0xff, BitOp->uiBitBufferSize);
    return 0;
}

/*
**
**  NAME
**    boSetBit
**
**  DESCRIPTION
**    Set the bit in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to set within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the bit was set, 1 if there was an error.
**
*/
static inline int boSetBit(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while setting bits
    */
    if((BitOp == NULL) || (BitOp->uiMaxBits <= uiPos))
        return 1;

    mask = (unsigned char)( 0x80 >> (uiPos & 7));

    BitOp->pucBitBuffer[uiPos >> 3] |= mask;

    return 0;
}
/*
**
**  NAME
**    boIsBitSet
**
**  DESCRIPTION
**    Checks for the bit set in iPos of bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - structure that holds the bit buffer
**    int     - the position number in the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if bit not set, 1 if bit is set.
**
*/
static inline int boIsBitSet(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while setting bits
    */
    if((BitOp == NULL) || (BitOp->uiMaxBits <= uiPos))
        return 0;

    mask = (unsigned char)(0x80 >> (uiPos & 7));

    return (mask & BitOp->pucBitBuffer[uiPos >> 3]);
}

/*
**
**  NAME
**    boClearBit
**
**  DESCRIPTION
**    Clear the bit in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to clear within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the bit was cleared, 1 if there was an error.
**
*/
static inline void boClearBit(BITOP *BitOp, unsigned int uiPos)
{
    unsigned char  mask;

    /*
    **  Sanity Check while clearing bits
    */
    if((BitOp == NULL) || (BitOp->uiMaxBits <= uiPos))
        return;

    mask = (unsigned char)(0x80 >> (uiPos & 7));

    BitOp->pucBitBuffer[uiPos >> 3] &= ~mask;
}

/*
**
**  NAME
**    boClearByte
**
**  DESCRIPTION
**    Clear the byte in the specified position within the bit buffer.
**
**  FORMAL INPUTS
**    BITOP * - the structure with the bit buffer
**    int     - the position to clear within the bit buffer
**
**  FORMAL OUTPUTS
**    int - 0 if the byte was cleared, 1 if there was an error.
**
*/
static inline void boClearByte(BITOP *BitOp, unsigned int uiPos)
{
    /*
    **  Sanity Check while clearing bytes
    */
    if((BitOp == NULL) || (BitOp->uiMaxBits <= uiPos))
        return;

    BitOp->pucBitBuffer[uiPos >> 3] = 0;
}

/*
 **
 **  NAME
 **    boFreeBITOP
 **
 **  DESCRIPTION
 **    Frees memory created by boInitBITOP - specifically
 **    BitOp->pucBitBuffer
 **
 **    NOTE:
 **    !!! ONLY USE THIS FUNCTION IF YOU USED boInitBITOP !!!
 **
 **  FORMAL INPUTS
 **    BITOP * - the structure initially passed to boInitBITOP
 **
 **  FORMAL OUTPUTS
 **    void function
 **
 **/
static inline void boFreeBITOP(BITOP *BitOp)
{
    if((BitOp == NULL) || (BitOp->pucBitBuffer == NULL))
        return;

    free(BitOp->pucBitBuffer);
    BitOp->pucBitBuffer = NULL;
}

#endif /* _BITOPT_FUNCS_H_ */
