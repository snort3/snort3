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


#ifndef ETHERTYPES_H
#define ETHERTYPES_H

/*
 * this file contained the ethertypes for all of the various protocols.
 * 
 * This is ONLY useful when protocols are chained and specificy the next
 * protocol by name rather than by an ID.  MOST protocols do NOT need to
 * entered into this file.
 *
 *  Defined at:
 * http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
 */


const uint16_t TRANS_ETHER_BRIDGING_ETHERTYPE = 0x6558;
const uint16_t PPP_ETHERTYPE = 0x880B;

#endif
