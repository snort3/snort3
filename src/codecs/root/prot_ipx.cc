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

#include "generators.h"
#include "decode.h"  
#include "static_include.h"
#include "decoder_includes.h"



#define ETHERNET_TYPE_IPX             0x8137

/*
 * Function: DecodeIPX(uint8_t *, uint32_t)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(const uint8_t*, uint32_t, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IPX is not supported.\n"););

    dc.ipx++;

    if (p->greh != NULL)
        dc.gre_ipx++;
}

static const char* name = "ipx_decode";

static const CodecApi ipx_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_IPX},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    Ipx::Decode,
};


