//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

// dce_tcp_paf.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_TCP_PAF_H
#define DCE_TCP_PAF_H

#include "dce_common.h"
#include "stream/stream_splitter.h"

enum DCE2_PafTcpStates
{
    DCE2_PAF_TCP_STATES__0 = 0,
    DCE2_PAF_TCP_STATES__1,     // Major version
    DCE2_PAF_TCP_STATES__2,     // Minor version
    DCE2_PAF_TCP_STATES__3,     // PDU type
    DCE2_PAF_TCP_STATES__4,     // Byte order
    DCE2_PAF_TCP_STATES__5,
    DCE2_PAF_TCP_STATES__6,
    DCE2_PAF_TCP_STATES__7,
    DCE2_PAF_TCP_STATES__8,     // First byte of fragment length
    DCE2_PAF_TCP_STATES__9      // Second byte of fragment length
};

// State tracker for DCE/RPC over TCP PAF
struct DCE2_PafTcpData
{
    DCE2_PafTcpStates paf_state;
    DceRpcBoFlag byte_order;
    uint16_t frag_len;
    bool autodetected;
};

class Dce2TcpSplitter : public snort::StreamSplitter
{
public:
    Dce2TcpSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    DCE2_PafTcpData state;
};

#endif

