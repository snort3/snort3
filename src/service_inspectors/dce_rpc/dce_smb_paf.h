//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_paf.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB_PAF_H
#define DCE_SMB_PAF_H

#include "stream/stream_splitter.h"

#define DCE2_SMB_PAF_SHIFT(x64, x8) { (x64) <<= 8; (x64) |= (uint64_t)(x8); }

// Enumerations for PAF states
enum DCE2_PafSmbStates
{
    DCE2_PAF_SMB_STATES__0 = 0,  // NetBIOS type
    DCE2_PAF_SMB_STATES__1,      // Added bit of NetBIOS length
    DCE2_PAF_SMB_STATES__2,      // First byte of NetBIOS length
    DCE2_PAF_SMB_STATES__3,      // Second byte of NetBIOS length
    // Junk states
    DCE2_PAF_SMB_STATES__4,      // 0xff
    DCE2_PAF_SMB_STATES__5,      // 'S'
    DCE2_PAF_SMB_STATES__6,      // 'M'
    DCE2_PAF_SMB_STATES__7       // 'B'
};

// State tracker for DCE/RPC over SMB PAF
struct DCE2_PafSmbData
{
    DCE2_PafSmbStates paf_state;
    uint64_t nb_hdr;   // Enough for NetBIOS header and 4 bytes SMB header
};

class Dce2SmbSplitter : public snort::StreamSplitter
{
public:
    Dce2SmbSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

public:
    DCE2_PafSmbData state;
};

#endif

