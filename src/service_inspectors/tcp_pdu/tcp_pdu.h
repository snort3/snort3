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

// tcp_pdu.h author Russ Combs <rucombs@cisco.com>

// provides a simple flush mechanism for TCP PDUs with
// a fixed size header containing a length field

#ifndef TCP_PDU_H
#define TCP_PDU_H

#include "framework/counts.h"
#include "main/snort_types.h"
#include "stream/stream_splitter.h"

struct TcpPduConfig
{
    unsigned size = 0;
    unsigned offset = 0;
    unsigned skip = 0;
    bool relative = false;
};

struct PduCounts
{
    PegCount scans;
    PegCount flushes;
    PegCount aborts;
};

extern THREAD_LOCAL PduCounts pdu_counts;

class TcpPduSplitter : public snort::StreamSplitter
{
public:
    TcpPduSplitter(bool b, TcpPduConfig& c) : snort::StreamSplitter(b), config(c) { }

    bool is_paf() override { return true; }

    Status scan(struct snort::Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override;

private:
    TcpPduConfig config;
    unsigned index = 0;
    uint32_t value = 0;
};

#endif

