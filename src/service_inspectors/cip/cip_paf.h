//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// cip_paf.h author RA/Cisco

/* Description: Protocol-Aware Flushing (PAF) code for the CIP inspector. */

#ifndef CIP_PAF_H
#define CIP_PAF_H

#include "stream/stream_splitter.h"

#include "cip.h"

#define CIP_MAX_OCTETS 15000 // using standard max ethernet frame times 10

/* State-tracking structs */
enum cip_paf_state
{
    CIP_PAF_STATE__COMMAND_1 = 0,
    CIP_PAF_STATE__COMMAND_2,
    CIP_PAF_STATE__LENGTH_1,
    CIP_PAF_STATE__LENGTH_2,
    CIP_PAF_STATE__SET_FLUSH,
    CIP_PAF_STATE__INVALID
};

struct cip_paf_data
{
    cip_paf_state paf_state;
    uint16_t enip_length;
    uint32_t bytes_seen;
};

class CipSplitter : public snort::StreamSplitter
{
public:
    CipSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

public:
    cip_paf_data state;
};

#endif /* CIP_PAF_H */

