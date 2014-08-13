/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#ifndef STREAM5_TCP_H
#define STREAM5_TCP_H

#include "flow/flow.h"
#include "stream/stream_api.h"
#include "protocols/packet.h"
#include "target_based/sftarget_protocol_reference.h"
#include "framework/bits.h"

struct StreamTcpConfig
{
    uint16_t policy;
    uint16_t reassembly_policy;
    uint16_t flags;
    uint16_t flush_factor;
    uint16_t session_on_syn;

    uint32_t session_timeout;
    uint32_t max_window;
    uint32_t overlap_limit;

    uint32_t max_queued_bytes;
    uint32_t max_queued_segs;

    uint32_t max_consec_small_segs;
    uint32_t max_consec_small_seg_size;

    int hs_timeout;
    int footprint;
    unsigned paf_max;

    PortList small_seg_ignore;

    StreamTcpConfig();

    void set_port(Port port, bool c2s, bool s2c);
    void set_proto(unsigned proto_ordinal, bool c2s, bool s2c);
    void add_proto(const char* svc, bool c2s, bool s2c);
};

// misc stuff
int Stream5VerifyTcpConfig(SnortConfig*, StreamTcpConfig *);

Session* get_tcp_session(Flow*);
StreamTcpConfig* get_tcp_cfg(Inspector*);

void tcp_sinit();
void tcp_sterm();
void tcp_sum();
void tcp_stats();
void tcp_reset_stats();
void tcp_show(StreamTcpConfig*);

// Stream support
int Stream5FlushListener(Packet*, Flow*);
int Stream5FlushTalker(Packet*, Flow*);
int Stream5FlushClient(Packet*, Flow*);
int Stream5FlushServer(Packet*, Flow*);
void Stream5TcpSessionClear(Flow*);
char Stream5GetReassemblyDirectionTcp(Flow*);

int Stream5AddSessionAlertTcp(Flow*, Packet*, uint32_t gid, uint32_t sid);
int Stream5CheckSessionAlertTcp(Flow*, Packet*, uint32_t gid, uint32_t sid);
int Stream5UpdateSessionAlertTcp(
    Flow*, Packet*, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second);

void Stream5SetExtraDataTcp(Flow*, Packet*, uint32_t flag);
void Stream5ClearExtraDataTcp(Flow*, Packet*, uint32_t flag);

bool Stream5GetReassemblyFlushPolicyTcp(Flow*, char dir);

char Stream5IsStreamSequencedTcp(Flow*, char dir);
int Stream5MissingInReassembledTcp(Flow*, char dir);
char Stream5PacketsMissingTcp(Flow*, char dir);

void* get_paf_config(StreamTcpConfig*);
void** Stream5GetPAFUserDataTcp(Flow*, bool to_server);
bool Stream5IsPafActiveTcp(Flow*, bool to_server);

void Stream5SetSplitterTcp(Flow*, bool c2s, StreamSplitter*);
StreamSplitter* Stream5GetSplitterTcp(Flow*, bool c2s);

int GetTcpRebuiltPackets(Packet*, Flow*, PacketIterator, void *userdata);
int GetTcpStreamSegments(Packet*, Flow*, StreamSegmentIterator, void *userdata);

void s5TcpSetSynSessionStatus(SnortConfig*, uint16_t status);
void s5TcpUnsetSynSessionStatus(SnortConfig*, uint16_t status);

#endif

