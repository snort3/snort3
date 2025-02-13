//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// mms_splitter.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_paf.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_paf.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef MMS_SPLITTER__H
#define MMS_SPLITTER__H

// MMS Splitter provides a means of normalizing MMS traffic. It does so by
// splitting apart or reassembling pipelined messages as necessary, and then
// parses and strips off the encapsulation layers leaving only the MMS
// message itself for analysis.

#include "stream/stream_splitter.h"

struct CurPacketContext
{
    uint8_t* data;
    uint32_t len;
    uint32_t start_offset;
    uint32_t splitter_offset;
    uint32_t exit_offset;
};

class MmsSplitter : public snort::StreamSplitter
{
public:
    MmsSplitter(bool);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }
};

#endif

