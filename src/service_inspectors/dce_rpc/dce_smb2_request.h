//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_request.h author Bhargava Jandhyala <bjandhya@cisco.com>

#ifndef DCE_SMB2_REQUEST_H
#define DCE_SMB2_REQUEST_H

// This provides request trackers for SMBv2.
// Request trackers are used to track CREATE, READ and WRITE requests

#include "dce_smb2.h"

class Dce2Smb2RequestTracker
{
public:

    Dce2Smb2RequestTracker() = delete;
    Dce2Smb2RequestTracker(const Dce2Smb2RequestTracker& arg) = delete;
    Dce2Smb2RequestTracker& operator=(const Dce2Smb2RequestTracker& arg) = delete;

    Dce2Smb2RequestTracker(uint64_t file_id_v, uint64_t offset_v = 0)
        : fname(nullptr), fname_len(0), file_id(file_id_v), offset(offset_v)
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET, "request tracker created\n");
    }

    Dce2Smb2RequestTracker(char* fname_v, uint16_t fname_len_v)
        : fname(fname_v), fname_len(fname_len_v), file_id(0), offset(0)
    {
	    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET, "request tracker created\n");
    }

    ~Dce2Smb2RequestTracker()
    {
        if (smb_module_is_up and (snort::is_packet_thread()))
        {
	        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET, "request tracker terminating\n");
        }
        if (fname)
            snort_free(fname);
    }

    uint64_t get_offset() { return offset; }
    uint64_t get_file_id() { return file_id; }
    char* get_file_name() { return fname; }
    uint16_t get_file_name_size() { return fname_len; }

private:
    char* fname;
    uint16_t fname_len;
    uint64_t file_id;
    uint64_t offset;
};

using Dce2Smb2RequestTrackerMap =
    std::unordered_map<Smb2MessageKey, Dce2Smb2RequestTracker*, Smb2KeyHash>;

#endif

