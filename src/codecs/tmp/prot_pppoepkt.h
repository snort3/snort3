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


#ifndef PROT_PPPOEPKT_H
#define PROT_PPPOEPKT_H

#include "encode.h"


#define PPPOE_HEADER_LEN 6

#define ETHERNET_TYPE_PPPoE_DISC 0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS 0x8864 /* session stage */


/* PPPoE types */
#define PPPoE_CODE_SESS 0x00 /* PPPoE session */
#define PPPoE_CODE_PADI 0x09 /* PPPoE Active Discovery Initiation */
#define PPPoE_CODE_PADO 0x07 /* PPPoE Active Discovery Offer */
#define PPPoE_CODE_PADR 0x19 /* PPPoE Active Discovery Request */
#define PPPoE_CODE_PADS 0x65 /* PPPoE Active Discovery Session-confirmation */
#define PPPoE_CODE_PADT 0xa7 /* PPPoE Active Discovery Terminate */

/* PPPoE tag types */
#define PPPoE_TAG_END_OF_LIST 0x0000
#define PPPoE_TAG_SERVICE_NAME 0x0101
#define PPPoE_TAG_AC_NAME 0x0102
#define PPPoE_TAG_HOST_UNIQ 0x0103
#define PPPoE_TAG_AC_COOKIE 0x0104
#define PPPoE_TAG_VENDOR_SPECIFIC 0x0105
#define PPPoE_TAG_RELAY_SESSION_ID 0x0110
#define PPPoE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPoE_TAG_AC_SYSTEM_ERROR 0x0202
#define PPPoE_TAG_GENERIC_ERROR 0x0203


void DecodePPPoEPkt(const uint8_t *, const uint32_t, Packet *);
EncStatus PPPoE_Encode (EncState* enc, Buffer* in, Buffer* out);


#endif

