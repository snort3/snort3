//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// file_decomp_zip_fuzz.cc author Jason Crowder <jasocrow@cisco.com>

#include "../file_decomp_zip.h"

using namespace snort;

// Matches DEFAULT_DECOMP from mime/file_mime_config.h
// Duplicated here to avoid pulling in dependencies
#define DEFAULT_DECOMP 100000

uint8_t out_data[DEFAULT_DECOMP] = { };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint32_t clamped_size = (uint32_t)size;

    if (size > UINT32_MAX)
    {
        return 0;
    }

    fd_session_t* fd = File_Decomp_New();

    fd->File_Type = FILE_TYPE_ZIP;
    fd->Next_In = data;
    fd->Avail_In = clamped_size;
    fd->Next_Out = out_data;
    fd->Avail_Out = sizeof(out_data);

    File_Decomp_Init_ZIP(fd);

    File_Decomp_ZIP(fd);

    File_Decomp_End_ZIP(fd);

    File_Decomp_Free(fd);

    return 0;
}
