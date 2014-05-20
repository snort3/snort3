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


#ifndef PROTOCOL_IDS_H
#define PROTOCOL_IDS_H

/*****************************************************************
 *****  NOTE:   Protocols are only included in this file when ****
 *****          their IDs are needed throughout multipled     ****
 *****          files.  If a protocol ID is only need in one  ****
 *****          file, define that number as a                 ****
 *****          static const uint16_t ID_NAME = ZZZZ          ****
 *****          in the specific file.                         ****
 ****************************************************************/


/*
 *  PROTOCOL ID'S By Range
 *   0    (0x0000) -   255  (0x00FF)  --> IP protocols
 *   256  (0x0100) -  1535  (0x05FF)  --> protocols without IDs (teredo, gtp)
 *  1536  (0x6000) -  65536 (0xFFFF)  --> Ethertypes
 */



/*
 * Below is a partial list of protocol numbers for the IP protocols.
 *  Defined at:
 * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */

const uint16_t IPPROTO_ID_HOPOPTS = 0;
const uint16_t IPPROTO_ID_ICMPV4 = 1;
const uint16_t IPPROTO_ID_IPIP = 4;
const uint16_t IPPROTO_ID_IPV6 = 41;
const uint16_t IPPROTO_ID_ROUTING = 43;
const uint16_t IPPROTO_ID_FRAGMENT = 44;
const uint16_t IPPROTO_ID_ESP = 50;
const uint16_t IPPROTO_ID_AH = 51; // RFC 4302
const uint16_t IPPROTO_ID_ICMPV6 = 58;
const uint16_t IPPROTO_ID_NONEXT = 59;
const uint16_t IPPROTO_ID_DSTOPTS = 60;


/*
 *  Undefined Protocol!
 */

const uint16_t FINISHED_DECODE = 0x0100;  // Indicates Codecs have succesfully decoded packet
const uint16_t PROTOCOL_TEREDO = 0x0101;
const uint16_t PROTOCOL_GTP = 0x0102;




/*
 * Below is a partial list of ethertypes.
 *  Defined at:
 *
 *  Defined at:
 * http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
 */


const uint16_t ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558;
const uint16_t ETHERTYPE_IPV4 = 0x0800;
const uint16_t ETHERTYPE_IPV6 = 0x86dd;
const uint16_t ETHERTYPE_PPP = 0x880B;
const uint16_t ETHERTYPE_IPX = 0x8137;


#endif


