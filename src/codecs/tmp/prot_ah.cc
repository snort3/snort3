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
#include "prot_ah.h"

#include "prot_ipv4.h"


//--------------------------------------------------------------------
// decode.c::ESP
//--------------------------------------------------------------------

/* Function: DecodeAH
 *
 * Purpose: Decode Authentication Header
 *
 * NOTE: This is for IPv4 Auth Headers, we leave IPv6 to do its own
 * work.
 *
 */
void DecodeAH(const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *ah = (IP6Extension *)pkt;
    uint8_t extlen = sizeof(*ah) + (ah->ip6e_len << 2);

    if (extlen > len)
    {
        return;
    }

    PushLayer(PROTO_AH, p, pkt, extlen);

    DecodeIPv4Proto(ah->ip6e_nxt, pkt+extlen, len-extlen, p);
}


static const char* name = "ah_decode";

static const CodecApi ah_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {IPPROTO_AH},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    AH::DecodeAH,
};



