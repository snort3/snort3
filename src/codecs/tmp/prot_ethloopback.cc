/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
*/



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "daq.h"

#include "prot_ethloopback.h"
#include "decoder_includes.h"
#include "static_include.h"
#include "framework/codec.h"

static THREAD_LOCAL SimpleStats loopbackstats;
static SimpleStats gloopbackstats;

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static const char* name = "ethloopback_decode";
    #define ETHERNET_TYPE_LOOP 0x9000

/*
 * Function: DecodeEthLoopback(uint8_t *, uint32_t)
 *
 * Purpose: Just like IPX, it's just for counting.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */

 // ADD STATIC AFTER REMOVED FROM header file
bool EthLoopback::DecodeEthLoopback(const uint8_t *, const DAQ_PktHdr_t*, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id)
{

//    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "EthLoopback is not supported.\n"););

    loopbackstats.total_packets++;

//    if (p->greh != NULL)
//        dc.gre_loopback++;

    return true;
}





static const CodecApi ethLoopback_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_LOOP},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    EthLoopback::DecodeEthLoopback,
};

