//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembly.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include "detection/detect.h"
#include "flow/memcap.h"
#include "tcp_defs.h"

class TcpSession;
struct TcpTracker;

//-----------------------------------------------------------------
// we make a lot of TcpSegments so it is organized by member
// size/alignment requirements to minimize unused space
// ... however, use of padding below is critical, adjust if needed
//-----------------------------------------------------------------

struct TcpSegment
{
    static TcpSegment* init(struct Packet*, const struct timeval&, const uint8_t*, unsigned);
    static void term(TcpSegment*);
    bool is_retransmit(const uint8_t*, uint16_t size, uint32_t);

    uint8_t* payload;

    TcpSegment *prev;
    TcpSegment *next;

    struct timeval tv;

    uint32_t ts;
    uint32_t seq;

    uint16_t orig_dsize;
    uint16_t size;

    uint16_t urg_offset;
    uint8_t buffered;

    uint8_t data[1];     // variable length
};

enum FlushPolicy
{
    STREAM_FLPOLICY_IGNORE, /* ignore this traffic */
    STREAM_FLPOLICY_ON_ACK, /* protocol aware flushing (PAF) */
    STREAM_FLPOLICY_ON_DATA, /* protocol aware ips */
};

extern THREAD_LOCAL Packet* s5_pkt;
extern THREAD_LOCAL Memcap* tcp_memcap;

void RetransmitProcess(Packet* p, TcpSession*);
void RetransmitHandle(Packet* p, TcpSession* tcpssn);

void purge_all(TcpTracker *st);
int flush_stream(TcpSession *tcpssn, TcpTracker *st, Packet *p, uint32_t dir);
int purge_flushed_ackd(TcpSession *tcpssn, TcpTracker *st);
void FlushQueuedSegs(Flow* flow, TcpSession* tcpssn, bool clear, Packet* p = nullptr);
int StreamQueue(TcpTracker *st, Packet *p, TcpDataBlock *tdb, TcpSession *tcpssn);
int AddStreamNode(TcpTracker *st, Packet *p, TcpDataBlock* tdb, int16_t len, uint32_t slide,
        uint32_t trunc, uint32_t seq, TcpSegment *left);
uint32_t SegsToFlush(const TcpTracker* st, unsigned max);
int CheckFlushPolicyOnData(TcpSession *, TcpTracker *, TcpTracker *, Packet *);
int CheckFlushPolicyOnAck(TcpSession *, TcpTracker *, TcpTracker *, Packet *);

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
void SetPacketHeaderFoo(TcpSession* tcpssn, const Packet* p);
void GetPacketHeaderFoo( const TcpSession* tcpssn, DAQ_PktHdr_t* pkth, uint32_t dir);
void SwapPacketHeaderFoo(TcpSession* tcpssn);
#endif

#endif
