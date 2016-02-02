//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_config.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 22, 2015

#ifndef TCP_STREAM_CONFIG_H
#define TCP_STREAM_CONFIG_H

#include "tcp_defs.h"

class TcpStreamConfig
{
public:
    TcpStreamConfig(void);

    bool require_3whs(void);
    bool midstream_allowed(Packet*);
    int verify_config(SnortConfig*);
    void show_config(void);
    static void show_config(TcpStreamConfig*);

    StreamPolicy policy;
    ReassemblyPolicy reassembly_policy;

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
};

#endif

