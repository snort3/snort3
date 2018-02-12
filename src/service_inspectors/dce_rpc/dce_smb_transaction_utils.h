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

// dce_smb_transaction_utils.h author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB_TRANSACTION_UTILS_H
#define DCE_SMB_TRANSACTION_UTILS_H

#include "dce_smb.h"

DCE2_Ret DCE2_SmbTransactionGetName(const uint8_t* nb_ptr,
    uint32_t nb_len, uint16_t bcc, bool unicode);

DCE2_Ret DCE2_SmbValidateTransactionFields(
    const uint8_t* smb_hdr_ptr,
    const uint8_t* nb_ptr, const uint32_t nb_len, const uint16_t bcc,
    const uint32_t tdcnt, const uint32_t tpcnt,
    const uint32_t dcnt, const uint32_t doff, const uint32_t ddisp,
    const uint32_t pcnt, const uint32_t poff, const uint32_t pdisp);

DCE2_Ret DCE2_SmbValidateTransactionSent(
    uint32_t dsent, uint32_t dcnt, uint32_t tdcnt,
    uint32_t psent, uint32_t pcnt, uint32_t tpcnt);

DCE2_Ret DCE2_SmbBufferTransactionData(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* data_ptr, uint16_t dcnt, uint16_t ddisp);

DCE2_Ret DCE2_SmbBufferTransactionParameters(DCE2_SmbTransactionTracker* ttracker,
    const uint8_t* param_ptr, uint16_t pcnt, uint16_t pdisp);

DCE2_Ret DCE2_SmbCheckTotalCount(const uint32_t tcnt, const uint32_t cnt, const uint32_t
    disp);

inline bool DCE2_SmbFileUpload(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__UPLOAD;
}

inline bool DCE2_SmbFileDownload(DCE2_SmbFileDirection dir)
{
    return dir == DCE2_SMB_FILE_DIRECTION__DOWNLOAD;
}

#endif

