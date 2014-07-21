/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// cd_icmp4_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_icmp4_module.h"

// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap icmp4_rules[] =
{
    { DECODE_ICMP_DGRAM_LT_ICMPHDR, "(" CD_ICMP4_NAME ") ICMP Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR, "(" CD_ICMP4_NAME ") ICMP Timestamp Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_ADDRHDR, "(" CD_ICMP4_NAME ") ICMP Address Header Truncated" },
    { DECODE_ICMP_ORIG_IP_TRUNCATED, "(" CD_ICMP4_NAME ") ICMP Original IP Header Truncated" },
    { DECODE_ICMP_ORIG_IP_VER_MISMATCH, "(" CD_ICMP4_NAME ") ICMP version and Original IP Header versions differ" },
    { DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP, "(" CD_ICMP4_NAME ") ICMP Original Datagram Length < Original IP Header Length" },
    { DECODE_ICMP_ORIG_PAYLOAD_LT_64, "(" CD_ICMP4_NAME ") ICMP Original IP Payload < 64 bits" },
    { DECODE_ICMP_ORIG_PAYLOAD_GT_576, "(" CD_ICMP4_NAME ") ICMP Origianl IP Payload > 576 bytes" },
    { DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET, "(" CD_ICMP4_NAME ") ICMP Original IP Fragmented and Offset Not 0" },
    { DECODE_ICMP4_DST_MULTICAST, "(" CD_ICMP4_NAME ") ICMP4 packet to multicast dest address" },
    { DECODE_ICMP4_DST_BROADCAST, "(" CD_ICMP4_NAME ") ICMP4 packet to broadcast dest address" },
    { DECODE_ICMP4_TYPE_OTHER, "(" CD_ICMP4_NAME ") ICMP4 type other" },
    { DECODE_ICMP_PING_NMAP, "(" CD_ICMP4_NAME ") ICMP PING NMAP" },
    { DECODE_ICMP_ICMPENUM, "(" CD_ICMP4_NAME ") ICMP icmpenum v1.1.1" },
    { DECODE_ICMP_REDIRECT_HOST, "(" CD_ICMP4_NAME ") ICMP redirect host" },
    { DECODE_ICMP_REDIRECT_NET, "(" CD_ICMP4_NAME ") ICMP redirect net" },
    { DECODE_ICMP_TRACEROUTE_IPOPTS, "(" CD_ICMP4_NAME ") ICMP traceroute ipopts" },
    { DECODE_ICMP_SOURCE_QUENCH, "(" CD_ICMP4_NAME ") ICMP Source Quench" },
    { DECODE_ICMP_BROADSCAN_SMURF_SCANNER, "(" CD_ICMP4_NAME ") Broadscan Smurf Scanner" },
    { DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED, "(" CD_ICMP4_NAME ") ICMP Destination Unreachable Communication with Destination Network is Administratively Prohibited" },
    { DECODE_ICMP_PATH_MTU_DOS, "(" CD_ICMP4_NAME ") ICMP PATH MTU denial of service attempt" },
    { DECODE_ICMP_DOS_ATTEMPT, "(" CD_ICMP4_NAME ") BAD-TRAFFIC linux ICMP header dos attempt" }, 
    { DECODE_ICMP4_HDR_TRUNC, "(" CD_ICMP4_NAME ") truncated ICMP4 header" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

Icmp4Module::Icmp4Module() : DecodeModule(CD_ICMP4_NAME)
{ }

const RuleMap* Icmp4Module::get_rules() const
{ return icmp4_rules; }

