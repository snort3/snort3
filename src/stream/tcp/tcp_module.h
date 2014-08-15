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

// tcp_module.h author Russ Combs <rucombs@cisco.com>

#ifndef TCP_MODULE_H
#define TCP_MODULE_H

#include <string>
#include <vector>

#include "snort_types.h"
#include "framework/module.h"
#include "main/thread.h"
#include "stream/stream.h"

#define GID_STREAM_TCP  129

#define STREAM_TCP_SYN_ON_EST                      1
#define STREAM_TCP_DATA_ON_SYN                     2
#define STREAM_TCP_DATA_ON_CLOSED                  3
#define STREAM_TCP_BAD_TIMESTAMP                   4
#define STREAM_TCP_BAD_SEGMENT                     5
#define STREAM_TCP_WINDOW_TOO_LARGE                6
#define STREAM_TCP_EXCESSIVE_TCP_OVERLAPS          7
#define STREAM_TCP_DATA_AFTER_RESET                8
#define STREAM_TCP_SESSION_HIJACKED_CLIENT         9
#define STREAM_TCP_SESSION_HIJACKED_SERVER        10
#define STREAM_TCP_DATA_WITHOUT_FLAGS             11
#define STREAM_TCP_SMALL_SEGMENT                  12
#define STREAM_TCP_4WAY_HANDSHAKE                 13
#define STREAM_TCP_NO_TIMESTAMP                   14
#define STREAM_TCP_BAD_RST                        15
#define STREAM_TCP_BAD_FIN                        16
#define STREAM_TCP_BAD_ACK                        17
#define STREAM_TCP_DATA_AFTER_RST_RCVD            18
#define STREAM_TCP_WINDOW_SLAM                    19
#define STREAM_TCP_NO_3WHS                        20

extern const char* tcp_pegs[];
extern THREAD_LOCAL struct TcpStats tcpStats;
extern THREAD_LOCAL ProfileStats s5TcpPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpNewSessPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpStatePerfStats;
extern THREAD_LOCAL ProfileStats s5TcpDataPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpInsertPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpPAFPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpFlushPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpBuildPacketPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpProcessRebuiltPerfStats;
extern THREAD_LOCAL ProfileStats streamSizePerfStats;

//-------------------------------------------------------------------------
// stream_tcp module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_tcp"

struct SnortConfig;
struct StreamTcpConfig;

class StreamTcpModule : public Module
{
public:
    StreamTcpModule();
    ~StreamTcpModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    const RuleMap* get_rules() const;

    unsigned get_gid() const
    { return GID_STREAM_TCP; };

    StreamTcpConfig* get_data();

    ProfileStats* get_profile(unsigned, const char*&, const char*&) const;
    const char** get_pegs() const;
    PegCount* get_counts() const;

private:
    StreamTcpConfig* config;
};

#endif

