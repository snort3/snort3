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


#ifndef UNDEFINED_PROTOCOLS_H
#define UNDEFINED_PROTOCOLS_H

/*
 *  PROTOCOL ID'S By Range
 *   0    (0x0000) -   255  (0x00FF)  --> Ip protocols
 *   256  (0x0100) -  1535  (0x05FF)  -->  random protocols (teredo, gtp)
 *  1536  (0x6000) -  65536 (0xFFFF)  --> Ethertypes
 */
const uint16_t PROTOCOL_TEREDO = 0x0100;
const uint16_t PROTOCOL_GTP = 0x0101;

#endif
