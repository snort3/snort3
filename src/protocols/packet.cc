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

#include "packet.h"
#include "codecs/sf_protocols.h"
#include "log/messages.h"

void PacketClass::PushLayer(Packet *p, const Codec *cd, const uint8_t *hdr_start, uint32_t len)
{
    if ( p->next_layer < LAYER_MAX )
    {
        Layer* lyr = p->layers + p->next_layer++;
        lyr->proto = PROTO_TCP;
        lyr->cd = cd;
        lyr->start = (uint8_t*)hdr_start;
        lyr->length = (uint16_t)len;
    }
    else
    {
        LogMessage("(snort_decoder) WARNING: decoder got too many layers;"
            " next proto is something.\n");
    }
}