//--------------------------------------------------------------------------
// Copyright (C) 2018-2026 Cisco and/or its affiliates. All rights reserved.
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
//
// s7comm_paf.h author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifndef S7COMM_PAF__H
#define S7COMM_PAF__H

// Protocol-Aware Flushing (PAF) code for the S7commplus inspector.

#include "stream/stream_splitter.h"

enum s7commplus_paf_state_t : uint8_t
{
    S7COMMPLUS_PAF_STATE__TPKT_VER = 0,
    S7COMMPLUS_PAF_STATE__TPKT_RESERVED,
    S7COMMPLUS_PAF_STATE__TPKT_LEN_1,
    S7COMMPLUS_PAF_STATE__TPKT_LEN_2,
    S7COMMPLUS_PAF_STATE__COTP_LEN,
    S7COMMPLUS_PAF_STATE__COTP_PDU_TYPE,
    S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_1,
    S7COMMPLUS_PAF_STATE__COTP_CR_DST_REF_2,
    S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_1,
    S7COMMPLUS_PAF_STATE__COTP_CR_SRC_REF_2,
    S7COMMPLUS_PAF_STATE__COTP_CR_CLASS_OPTIONS,
    S7COMMPLUS_PAF_STATE__COTP_DT_TPDU_NUM_EOT,
    S7COMMPLUS_PAF_STATE__S7_PROTOCOL_ID,
    S7COMMPLUS_PAF_STATE__MAX
};

inline s7commplus_paf_state_t& operator++(s7commplus_paf_state_t& state)
{
    if(state >= S7COMMPLUS_PAF_STATE__MAX)
    {
        state = S7COMMPLUS_PAF_STATE__MAX;
    }
    else
    {
        state = static_cast<s7commplus_paf_state_t>(static_cast<uint8_t>(state) + 1);
    }
    return state;
}

class S7commplusSplitter : public snort::StreamSplitter
{
public:
    S7commplusSplitter(bool);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }

private:

    void reset_state();

    s7commplus_paf_state_t state;
    uint16_t tpkt_length;
};

#endif

