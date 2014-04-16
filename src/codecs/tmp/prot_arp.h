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


#ifndef PROT_ARP_H
#define PROT_ARP_H

#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_ARP             0x0806

#define ARPOP_REQUEST   1    /* ARP request                  */
#define ARPOP_REPLY     2    /* ARP reply                    */
#define ARPOP_RREQUEST  3    /* RARP request                 */
#define ARPOP_RREPLY    4    /* RARP reply                   */


void DecodeARP(const uint8_t *, uint32_t, Packet *);

#endif
