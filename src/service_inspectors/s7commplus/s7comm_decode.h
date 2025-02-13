//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
//
// s7comm_decode.h author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifndef S7COMM_DECODE_H
#define S7COMM_DECODE_H

namespace snort
{
struct Packet;
}

class S7commplusFlowData;

/* S7comm defines */
#define S7COMMPLUS_PDUTYPE_CONNECT                 0x01
#define S7COMMPLUS_PDUTYPE_DATA                    0x02
#define S7COMMPLUS_PDUTYPE_DATAFW1_5               0x03
#define S7COMMPLUS_PDUTYPE_KEEPALIVE               0xFF

#define COTP_HDR_LEN_FOR_S7COMMPLUS 2
#define COTP_HDR_PDU_TYPE_DATA  0xF0

#define S7COMM_PROTOCOL_ID      0x32
#define S7COMMPLUS_PROTOCOL_ID 0x72

#define TPKT_MIN_HDR_LEN 7     /* length field in TPKT header for S7comm */
#define TPKT_MAX_HDR_LEN       /* Undecided */
#define S7COMMPLUS_MIN_HDR_LEN 4
#define HDR_VERSION_TWO 0x02
#define INTEGRITY_PART_LEN 33 /* length of Integrity part in V3 Header packets */

/* Need 8 bytes for MBAP Header + Function Code */
#define S7COMMPLUS_MIN_LEN 8       this value needs to be decided

/* GIDs, SIDs, and Strings */
#define GENERATOR_SPP_S7COMMPLUS 149   /* matches generators.h */

#define S7COMMPLUS_BAD_LENGTH 1
#define S7COMMPLUS_BAD_PROTO_ID 2
#define S7COMMPLUS_RESERVED_FUNCTION 3

#define S7COMMPLUS_BAD_LENGTH_STR \
    "(spp_s7commplus): Length in S7commplus header does not match the length needed for the given S7commplus function."
#define S7COMMPLUS_BAD_PROTO_ID_STR "(spp_s7commplus): S7commplus protocol ID is non-zero."
#define S7COMMPLUS_RESERVED_FUNCTION_STR \
    "(spp_s7commplus): Reserved S7commplus function code in use."

bool S7commplusDecode(snort::Packet*, S7commplusFlowData* mfd);

#endif

