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


#ifndef PROT_EAPOL_H
#define PROT_EAPOL_H


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define ETHERNET_TYPE_EAPOL           0x888e


#ifndef NO_NON_ETHER_DECODER

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */


#endif // NO_NON_ETHER_DECODER

void DecodeEapol(const uint8_t *, uint32_t, Packet *);

#endif /* PROT_EAPOL_H */

