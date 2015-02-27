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

#ifndef STREAM_TCP_H
#define STREAM_TCP_H

#include "flow/flow.h"
#include "stream/stream_api.h"
#include "protocols/packet.h"
#include "framework/bits.h"

struct StreamTcpConfig
{
    uint16_t policy;
    uint16_t reassembly_policy;

    uint16_t flags;
    uint16_t flush_factor;

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

    bool require_3whs();
    bool midstream_allowed(Packet*);
};

// misc stuff
Session* get_tcp_session(Flow*);
StreamTcpConfig* get_tcp_cfg(Inspector*);

void tcp_sinit();
void tcp_sterm();
void tcp_sum();
void tcp_stats();
void tcp_reset_stats();
void tcp_show(StreamTcpConfig*);

// Stream support
int StreamFlushListener(Packet*, Flow*);
int StreamFlushTalker(Packet*, Flow*);
int StreamFlushClient(Packet*, Flow*);
int StreamFlushServer(Packet*, Flow*);
void StreamTcpSessionClear(Flow*);
char StreamGetReassemblyDirectionTcp(Flow*);

int StreamAddSessionAlertTcp(Flow*, Packet*, uint32_t gid, uint32_t sid);
int StreamCheckSessionAlertTcp(Flow*, Packet*, uint32_t gid, uint32_t sid);
int StreamUpdateSessionAlertTcp(
    Flow*, Packet*, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second);

void StreamSetExtraDataTcp(Flow*, Packet*, uint32_t flag);
void StreamClearExtraDataTcp(Flow*, Packet*, uint32_t flag);

bool StreamGetReassemblyFlushPolicyTcp(Flow*, char dir);

char StreamIsStreamSequencedTcp(Flow*, char dir);
int StreamMissingInReassembledTcp(Flow*, char dir);
char StreamPacketsMissingTcp(Flow*, char dir);

void* get_paf_config(StreamTcpConfig*);
void** StreamGetPAFUserDataTcp(Flow*, bool to_server);
bool StreamIsPafActiveTcp(Flow*, bool to_server);

void StreamSetSplitterTcp(Flow*, bool c2s, StreamSplitter*);
StreamSplitter* StreamGetSplitterTcp(Flow*, bool c2s);

int GetTcpRebuiltPackets(Packet*, Flow*, PacketIterator, void* userdata);
int GetTcpStreamSegments(Packet*, Flow*, StreamSegmentIterator, void* userdata);

#endif

