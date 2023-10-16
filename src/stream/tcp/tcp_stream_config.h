//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_config.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 22, 2015

#ifndef TCP_STREAM_CONFIG_H
#define TCP_STREAM_CONFIG_H

#include "protocols/packet.h"
#include "stream/tcp/tcp_defs.h"
#include "time/packet_time.h"

#define STREAM_CONFIG_SHOW_PACKETS             0x00000001
#define STREAM_CONFIG_NO_ASYNC_REASSEMBLY      0x00000002
#define STREAM_CONFIG_NO_REASSEMBLY            0x00000004

#define STREAM_DEFAULT_SSN_TIMEOUT  30

class TcpStreamConfig
{
public:
    TcpStreamConfig();

    bool require_3whs()
    {
        return hs_timeout >= 0;
    }

    bool midstream_allowed(snort::Packet* p)
    {
        if ( ( hs_timeout < 0 ) || ( p->pkth->ts.tv_sec - packet_first_time() < hs_timeout ) )
            return true;

        return false;
    }

    void show() const;

    StreamPolicy policy = StreamPolicy::OS_DEFAULT;

    uint16_t flags = 0;
    uint16_t flush_factor = 0;

    uint32_t session_timeout = STREAM_DEFAULT_SSN_TIMEOUT;
    uint32_t max_window = 0;
    uint32_t overlap_limit = 0;

    uint32_t max_queued_bytes = 4194304;
    uint32_t max_queued_segs = 3072;

    uint32_t max_consec_small_segs = STREAM_DEFAULT_CONSEC_SMALL_SEGS;
    uint32_t max_consec_small_seg_size = STREAM_DEFAULT_MAX_SMALL_SEG_SIZE;

    uint32_t paf_max = 16384;
    int hs_timeout = -1;

    bool no_ack;
};

#endif

