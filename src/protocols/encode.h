/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// @file    encode.h
// @author  Russ Combs <rcombs@sourcefire.com>

#ifndef ENCODE_H
#define ENCODE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode.h"

extern Packet *encode_pkt;
extern uint64_t total_rebuilt_pkts;

void Encode_Init(void);
void Encode_Term(void);

typedef enum {
    ENC_TCP_FIN,  ENC_TCP_RST,
    ENC_UNR_NET,  ENC_UNR_HOST,
    ENC_UNR_PORT, ENC_UNR_FW,
    ENC_TCP_PUSH,
    ENC_MAX
} EncodeType;

#define ENC_FLAG_FWD 0x80000000  // send in forward direction
#define ENC_FLAG_SEQ 0x40000000  // VAL bits contain seq adj
#define ENC_FLAG_ID  0x20000000  // use randomized IP ID
#define ENC_FLAG_NET 0x10000000  // stop after innermost network (ip4/6) layer
#define ENC_FLAG_DEF 0x08000000  // stop before innermost ip4 opts or ip6 frag header
#define ENC_FLAG_RAW 0x04000000  // don't encode outer eth header (this is raw ip)
#define ENC_FLAG_RES 0x03000000  // bits reserved for future use
#define ENC_FLAG_VAL 0x00FFFFFF  // bits for adjusting seq and/or ack

typedef uint32_t EncodeFlags;

// orig must be the current packet from the interface to
//   ensure proper encoding (not the reassembled packet).
// len is number of bytes in the encoded packet upon return
//   (or 0 if the returned pointer is null).
const uint8_t* Encode_Reject(
    EncodeType, EncodeFlags, const Packet* orig, uint32_t* len);

const uint8_t* Encode_Response(
    EncodeType, EncodeFlags, const Packet* orig, uint32_t* len,
    const uint8_t* payLoad, uint32_t payLen);

// allocate a Packet for later formatting (cloning)
Packet* Encode_New(void);

// release the allocated Packet
void Encode_Delete(Packet*);

// orig is the wire pkt; clone was obtained with New()
int Encode_Format(
    EncodeFlags, const Packet* orig, Packet* clone, PseudoPacketType);

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
int Encode_Format_With_DAQ_Info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    const DAQ_PktHdr_t*, uint32_t opaque);

#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
int Encode_Format_With_DAQ_Info (
    EncodeFlags f, const Packet* p, Packet* c, PseudoPacketType type,
    uint32_t opaque);
#endif

// update length and checksum fields in layers and caplen, etc.
void Encode_Update(Packet*);

// Set the destination MAC address
void Encode_SetDstMAC(uint8_t* );

static inline void Encode_SetPkt(Packet* p)
{
    encode_pkt = p;
}

static inline Packet* Encode_GetPkt(void)
{
    return encode_pkt;
}

static inline void Encode_Reset(void)
{
    Encode_SetPkt(NULL);
}

static inline void UpdateRebuiltPktCount(void)
{
    total_rebuilt_pkts++;
}

static inline uint64_t GetRebuiltPktCount(void)
{
    return total_rebuilt_pkts;
}

#endif

