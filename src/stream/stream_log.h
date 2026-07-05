//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// stream_log.h author Steven Baigal <sbaigal@cisco.com>

#ifndef STREAM_LOG_H
#define STREAM_LOG_H

#include "packet_io/packet_tracer.h"

namespace snort
{
struct Packet;
}

class StreamLog
{
public:
    static void add_ip_header_info(const snort::Packet&, bool add_eth = true);
    static void add_eth_header_info(const snort::Packet&);
    static void add_packet_type_info(const snort::Packet&);
    static void add_tunnel_info(const snort::Packet&);
    static bool stream_is_cbd_enabled();
};

void stream_daq_log_start();
void stream_daq_log_end(snort::Packet*);

void stream_log(const snort::Packet* p, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
void flow_log(const char* fmt, ...) __attribute__((format (printf, 1, 2)));

#endif // STREAM_LOG_H
