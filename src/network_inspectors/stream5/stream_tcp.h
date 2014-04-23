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

#ifndef STREAM5_TCP_H
#define STREAM5_TCP_H

#include "flow/flow.h"
#include "stream5/stream_api.h"

struct Stream5TcpConfig;

Stream5TcpConfig* Stream5ConfigTcp(SnortConfig* sc, char *args);void Stream5TcpConfigFree(Stream5TcpConfig *);

int Stream5VerifyTcpConfig(SnortConfig*, Stream5TcpConfig *);
void Stream5ResetTcp();

Session* get_tcp_session(Flow*);

// port filter foo
uint16_t* Stream5GetTcpPortList(void*, int& ignore_any);

void s5TcpSetPortFilterStatus(
    Stream5TcpConfig*, unsigned short port, uint16_t status);

void s5TcpUnsetPortFilterStatus(
    Stream5TcpConfig*, unsigned short port, uint16_t status);

int s5TcpGetPortFilterStatus(
    Stream5TcpConfig*, unsigned short port);

bool s5TcpIgnoreAny(Stream5TcpConfig*);

// misc stuff
void Stream5ResetTcpInstance(Stream5TcpConfig*);

void Stream_SumNormalizationStats(void);
void Stream_PrintNormalizationStats(void);
void Stream_ResetNormalizationStats(void);

void tcp_sinit(Stream5Config*);
void tcp_sterm();
void tcp_sum();
void tcp_stats();
void tcp_reset_stats();
void tcp_show(Stream5TcpConfig*);

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

uint32_t Stream5GetFlushPointTcp(Flow*, char dir);
void Stream5SetFlushPointTcp(Flow*, char dir, uint32_t flush_point);

char Stream5SetReassemblyTcp(Flow*, FlushPolicy, char dir, char flags);
char Stream5GetReassemblyFlushPolicyTcp(Flow*, char dir);

char Stream5IsStreamSequencedTcp(Flow*, char dir);
int Stream5MissingInReassembledTcp(Flow*, char dir);
char Stream5PacketsMissingTcp(Flow*, char dir);

void* get_paf_config(Stream5TcpConfig*);
void** Stream5GetPAFUserDataTcp(Flow*, bool to_server);
bool Stream5IsPafActiveTcp(Flow*, bool to_server);
bool Stream5ActivatePafTcp(Flow*, bool to_server);

int GetTcpRebuiltPackets(Packet*, Flow*, PacketIterator, void *userdata);
int GetTcpStreamSegments(Packet*, Flow*, StreamSegmentIterator, void *userdata);

void s5TcpSetSynSessionStatus(SnortConfig*, uint16_t status);
void s5TcpUnsetSynSessionStatus(SnortConfig*, uint16_t status);

#endif

