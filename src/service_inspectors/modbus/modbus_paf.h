//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// modbus_paf.h author Ryan Jordan

#ifndef MODBUS_PAF__H
#define MODBUS_PAF__H

// Protocol-Aware Flushing (PAF) code for the Modbus preprocessor.

#include "stream/stream_splitter.h"

enum modbus_paf_state_t
{
    MODBUS_PAF_STATE__TRANS_ID_1,
    MODBUS_PAF_STATE__TRANS_ID_2,
    MODBUS_PAF_STATE__PROTO_ID_1,
    MODBUS_PAF_STATE__PROTO_ID_2,
    MODBUS_PAF_STATE__LENGTH_1,
    MODBUS_PAF_STATE__LENGTH_2,
    MODBUS_PAF_STATE__SET_FLUSH
};

class ModbusSplitter : public snort::StreamSplitter
{
public:
    ModbusSplitter(bool);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    modbus_paf_state_t state;
    uint16_t modbus_length;
};

#endif

