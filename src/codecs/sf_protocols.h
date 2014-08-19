/* $Id: sf_protocols.h,v 1.10 2013-02-07 17:51:29 ssturges Exp $ */
/****************************************************************************
 *
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef SF_PROTOCOLS_H
#define SF_PROTOCOLS_H

typedef enum {
    PROTO_ETH,        // DecodeEthPkt

    PROTO_IP4,        // DecodeIP
                      // DecodeIPOptions - handled with IP4
    PROTO_ICMP4,      // DecodeICMP
    PROTO_ICMP_IP4,   // DecodeICMPEmbeddedIP

    PROTO_UDP,        // DecodeUDP
    PROTO_TCP,        // DecodeTCP
                      // DecodeTCPOptions - handled with TCP

    PROTO_IP6,        // DecodeIPV6
                      // DecodeIPV6Extensions - nothing to do here, calls below
    PROTO_IP6_HOP_OPTS,  // DecodeIPV6Options - ip6 hop, dst, rte, and frag exts
    PROTO_IP6_DST_OPTS,
    PROTO_ICMP6,      // DecodeICMP6
    PROTO_ICMP_IP6,   // DecodeICMPEmbeddedIP6
    PROTO_VLAN,       // DecodeVlan
    PROTO_GRE,        // DecodeGRE
                      // DecodeTransBridging - basically same as DecodeEthPkt
    PROTO_ERSPAN,     // DecodeERSPANType2 and DecodeERSPANType3
    PROTO_PPPOE,      // DecodePPPoEPkt
    PROTO_PPP_ENCAP,  // DecodePppPktEncapsulated
    PROTO_MPLS,       // DecodeMPLS - decoder changes pkth len/caplen!
                      // DecodeEthOverMPLS - basically same as straight eth
    PROTO_ARP,        // DecodeARP
    PROTO_GTP,        // DecodeGTP
    PROTO_AH,         // DecodeAH - Authentication Header (IPSec stuff)

    PROTO_TR,         // DecodeTRPkt
    PROTO_FDDI,       // DecodeFDDIPkt
    PROTO_LSLL,       // DecodeLinuxSLLPkt sockaddr_ll for "any" device and 
                      // certain misbehaving link layer encapsulations
    PROTO_80211,      // DecodeIEEE80211Pkt
    PROTO_SLIP,       // DecodeSlipPkt - actually, based on header size, this
                      // must be CSLIP (TCP/IP header compression) but all it
                      // does is skip over the presumed header w/o expanding
                      // and then jumps into IP4 decoding only; also, the actual
                      // esc/end sequences must already have been removed because
                      // there is no attempt to do that.
    PROTO_L2I4,       // DecodeI4LRawIPPkt - always skips 2 bytes and then does
                      // IP4 decoding only
    PROTO_L2I4C,      // DecodeI4LCiscoIPPkt -always skips 4 bytes and then does
                      // IP4 decoding only
    PROTO_CHDLC,      // DecodeChdlcPkt - skips 4 bytes and decodes IP4 only.
    PROTO_PFLOG,      // DecodePflog
    PROTO_OLD_PFLOG,  // DecodeOldPflog
    PROTO_PPP,        // DecodePppPkt - weird - optionally skips addr and cntl
                      // bytes; what about flag and protocol?
                      // calls only DecodePppPktEncapsulated.
    PROTO_PPP_SERIAL, // DecodePppSerialPkt - also weird - requires addr, cntl,
                      // and proto (no flag) but optionally skips only 2 bytes
                      // (presumably the trailer w/chksum is already stripped)
                      // Calls either DecodePppPktEncapsulated or DecodeChdlcPkt.
    PROTO_ENC,        // DecodeEncPkt - skips 12 bytes and decodes IP4 only.
                      // (add family + "spi" + "flags" - don't know what this is)
    PROTO_EAP,        // DecodeEAP
    PROTO_EAPOL,      // DecodeEapol - leaf decoder
    PROTO_EAPOL_KEY,  // DecodeEapolKey - leaf decoder

    PROTO_MAX
} PROTO_ID;

                      // DecodeIPX - just counts; no decoding
                      // DecodeEthLoopback - same as ipx
                      // DecodeRawPkt - jumps straight into IP4 decoding
                      // there is nothing to do
                      // DecodeNullPkt - same as DecodeRawPkt


#endif // __PROTOCOLS_H__

