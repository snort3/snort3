//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// dnp3_paf.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Ryan Jordan

#ifndef DNP3_PAF_H
#define DNP3_PAF_H

// Protocol aware flushing for DNP3.

#include "stream/stream_splitter.h"

enum dnp3_paf_state
{
    DNP3_PAF_STATE__START_1 = 0,
    DNP3_PAF_STATE__START_2,
    DNP3_PAF_STATE__LENGTH,
    DNP3_PAF_STATE__SET_FLUSH
};

struct dnp3_paf_data
{
    dnp3_paf_state paf_state;
    uint8_t dnp3_length;
    uint16_t real_length;
};

class Dnp3Splitter : public snort::StreamSplitter
{
public:
    Dnp3Splitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

public:
    dnp3_paf_data state;
};

#endif

