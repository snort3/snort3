//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_commands.h author Bhargava Jandhyala <bjandhya@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB2_COMMANDS_H
#define DCE_SMB2_COMMANDS_H

#include "dce_smb_module.h"
#include "dce_smb_utils.h"
#include "dce_smb2_utils.h"
#include "detection/detection_util.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"

void DCE2_Smb2Setup(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint64_t sid, const uint8_t* smb_data, const uint8_t* end);

void DCE2_Smb2TreeConnect(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str, uint32_t tid);

void DCE2_Smb2TreeDisconnect(DCE2_Smb2SsnData*, const uint8_t* smb_data,
    const uint8_t* end, DCE2_Smb2SessionTracker* str, uint32_t tid);

void DCE2_Smb2Create(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, uint64_t mid, uint64_t sid, uint32_t tid);

void DCE2_Smb2Read(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid);

void DCE2_Smb2Write(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2SessionTracker* str,
    DCE2_Smb2TreeTracker* ttr, uint64_t mid);

void DCE2_Smb2SetInfo(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr);

bool DCE2_Smb2ProcessFileData(DCE2_Smb2SsnData*, const uint8_t* file_data,
    uint32_t data_size);

void DCE2_Smb2CloseCmd(DCE2_Smb2SsnData*, const Smb2Hdr*,
    const uint8_t* smb_data, const uint8_t* end, DCE2_Smb2TreeTracker* ttr,
    DCE2_Smb2SessionTracker* str);

void DCE2_Smb2Logoff(DCE2_Smb2SsnData*, const uint8_t* smb_data,
    const uint64_t sid);

#endif

