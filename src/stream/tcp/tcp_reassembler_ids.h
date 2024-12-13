//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembler_ids.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_REASSEMBLER_IDS_H
#define TCP_REASSEMBLER_IDS_H

#include <cstdint>

#include "protocols/packet.h"
#include "stream/stream.h"

#include "tcp_reassembler.h"
#include "tcp_reassembly_segments.h"

class TcpSegmentDescriptor;
class TcpSegmentNode;

class TcpReassemblerIds : public TcpReassemblerBase
{
public:
    TcpReassemblerIds(TcpStreamTracker& trk, TcpReassemblySegments& sl)
        : TcpReassemblerBase(trk, sl)
    { }

    ~TcpReassemblerIds() override
    { }

    int eval_flush_policy_on_ack(snort::Packet*) override;
    int eval_flush_policy_on_data(snort::Packet*) override;
    int eval_asymmetric_flush(snort::Packet*) override;
    int flush_stream(snort::Packet*, uint32_t dir, bool final_flush = false) override;

    FlushPolicy get_flush_policy() const override
    { return STREAM_FLPOLICY_ON_ACK; }

private:
    int32_t scan_data_post_ack(uint32_t* flags, snort::Packet*);
    bool has_seglist_hole(TcpSegmentNode&, uint32_t& total, uint32_t& flags);
    void skip_seglist_hole(snort::Packet*, uint32_t flags, int32_t flush_amt);
};

#endif
