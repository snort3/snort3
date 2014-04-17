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


#ifndef PROT_EAP_H
#define PROT_EAP_H


#ifndef NO_NON_ETHER_DECODER


/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d

#endif // NO_NON_ETHER_DECODER

void DecodeEAP(const uint8_t *, const uint32_t, Packet *);


#endif

