//--------------------------------------------------------------------------
// Copyright (C) 2015-2020 Cisco and/or its affiliates. All rights reserved.
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

// SMB2 file processing
// Author(s):  Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2.h"
#include "dce_smb2_commands.h"
#include "detection/detection_util.h"
#include "main/snort_debug.h"

using namespace snort;

static inline bool DCE2_Smb2FindSidTid(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    const uint32_t tid, DCE2_Smb2SessionTracker** str, DCE2_Smb2TreeTracker** ttr)
{
    *str = DCE2_Smb2FindSidInSsd(ssd, sid);
    if (!*str)
        return false;

    *ttr = (*str)->findTtracker(tid);
    if (!*ttr)
        return false;

    return true;
}

// FIXIT-L port fileCache related code along with
// DCE2_Smb2Init, DCE2_Smb2Close and DCE2_Smb2UpdateStats

static void DCE2_Smb2Inspect(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_hdr + SMB2_HEADER_LENGTH;
    uint16_t command = alignedNtohs(&(smb_hdr->command));
    DCE2_Smb2SessionTracker* str = nullptr;
    DCE2_Smb2TreeTracker* ttr = nullptr;

    uint64_t mid = Smb2Mid(smb_hdr);
    uint64_t sid = Smb2Sid(smb_hdr);
    uint32_t tid = Smb2Tid(smb_hdr);

    switch (command)
    {
    case SMB2_COM_CREATE:
        dce2_smb_stats.v2_crt++;
        DCE2_Smb2Create(ssd, smb_hdr, smb_data, end, mid, sid, tid);
        break;
    case SMB2_COM_READ:
        dce2_smb_stats.v2_read++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, &str, &ttr) or
            SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_read_ignored++;
            return;
        }

        DCE2_Smb2Read(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_WRITE:
        dce2_smb_stats.v2_wrt++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, &str, &ttr) or
            SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_wrt_ignored++;
            return;
        }

        DCE2_Smb2Write(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_SET_INFO:
        dce2_smb_stats.v2_stinf++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, &str, &ttr) or
            SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_stinf_ignored++;
            return;
        }

        DCE2_Smb2SetInfo(ssd, smb_hdr, smb_data, end, ttr);
        break;
    case SMB2_COM_CLOSE:
        dce2_smb_stats.v2_cls++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, &str, &ttr) or
            SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_cls_ignored++;
            return;
        }

        DCE2_Smb2CloseCmd(ssd, smb_hdr, smb_data, end, ttr);
        break;
    case SMB2_COM_TREE_CONNECT:
        dce2_smb_stats.v2_tree_cnct++;
        // This will always return session tracker
        str = DCE2_Smb2FindElseCreateSid(ssd, sid);
        if (str)
        {
            DCE2_Smb2TreeConnect(ssd, smb_hdr, smb_data, end, str, tid);
        }
        break;
    case SMB2_COM_TREE_DISCONNECT:
        dce2_smb_stats.v2_tree_discn++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, &str, &ttr))
        {
            dce2_smb_stats.v2_tree_discn_ignored++;
            return;
        }
        DCE2_Smb2TreeDisconnect(ssd, smb_data, end, str, tid);
        break;
    case SMB2_COM_SESSION_SETUP:
        dce2_smb_stats.v2_setup++;
        DCE2_Smb2Setup(ssd, smb_hdr, sid, smb_data, end);
        break;
    case SMB2_COM_LOGOFF:
        dce2_smb_stats.v2_logoff++;
        DCE2_Smb2Logoff(ssd, smb_data, sid);
        break;
    default:
        dce2_smb_stats.v2_msgs_uninspected++;
        break;
    }
}

// This is the main entry point for SMB2 processing.
void DCE2_Smb2Process(DCE2_Smb2SsnData* ssd)
{
    Packet* p = DetectionEngine::get_current_packet();
    const uint8_t* data_ptr = p->data;
    uint16_t data_len = p->dsize;

    // Check header length
    if (data_len < sizeof(NbssHdr) + SMB2_HEADER_LENGTH)
    {
        dce2_smb_stats.v2_hdr_err++;
        return;
    }

    // Process the header
    if (p->is_pdu_start())
    {
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(data_ptr + sizeof(NbssHdr));
        uint32_t next_command_offset;
        uint8_t compound_request_index = 0;
        // SMB protocol allows multiple smb commands to be grouped in a single packet.
        // So loop through to parse all the smb commands.
        // Reference: https://msdn.microsoft.com/en-us/library/cc246614.aspx
        // "A nonzero value for the NextCommand field in the SMB2 header indicates a compound
        // request. NextCommand in the SMB2 header of a request specifies an offset, in bytes,
        // from the beginning of the SMB2 header under consideration to the start of the 8-byte
        // aligned SMB2 header of the subsequent request. Such compounding can be used to append
        // multiple requests up to the maximum size<88> that is supported by the transport."
        do
        {
            DCE2_Smb2Inspect(ssd, smb_hdr, data_ptr +  data_len);
            // In case of message compounding, find the offset of the next smb command
            next_command_offset = alignedNtohl(&(smb_hdr->next_command));
            if (next_command_offset + (const uint8_t*)smb_hdr > (data_ptr + data_len))
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET,
                    (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
                dce2_smb_stats.v2_bad_next_cmd_offset++;
                return;
            }
            if (next_command_offset)
            {
                smb_hdr = (const Smb2Hdr*)((const uint8_t*)smb_hdr + next_command_offset);
                compound_request_index++;
            }

            if (compound_request_index > DCE2_ScSmbMaxCompound((dce2SmbProtoConf*)ssd->sd.config))
            {
                dce2_smb_stats.v2_cmpnd_req_lt_crossed++;
                return;
            }
        }
        while (next_command_offset and smb_hdr);
    }
    else if ( ssd->ftracker_tcp and (ssd->ftracker_tcp->smb2_pdu_state ==
        DCE2_SMB_PDU_STATE__RAW_DATA))
    {
        debug_logf(dce_smb_trace, nullptr, "Processing raw data\n");
        // continue processing raw data
        FileDirection dir = p->is_from_client() ? FILE_UPLOAD : FILE_DOWNLOAD;
        DCE2_Smb2ProcessFileData(ssd, data_ptr, data_len, dir);
        ssd->ftracker_tcp->file_offset += data_len;
    }
}

static inline void DCE2_Smb2FreeSessionData(void* str)
{
    DCE2_Smb2SessionTracker* stracker = (DCE2_Smb2SessionTracker*)str;
    DCE2_SmbSessionCacheRemove(stracker->get_session_id());
}

DCE2_Ret DCE2_Smb2InitData(DCE2_Smb2SsnData* ssd)
{
    memset(&ssd->sd, 0, sizeof(DCE2_SsnData));
    ssd->session_trackers.Init(DCE2_Smb2FreeSessionData);
    memset(&ssd->policy, 0, sizeof(DCE2_Policy));
    ssd->dialect_index = 0;
    ssd->ssn_state_flags = 0;
    ssd->ftracker_tcp = nullptr;
    ssd->max_file_depth = FileService::get_max_file_depth();
    return DCE2_RET__SUCCESS;
}

// Check whether the packet is smb2
DCE2_SmbVersion DCE2_Smb2Version(const Packet* p)
{
    // Only check reassembled SMB2 packet
    if ( p->has_paf_payload() and
            (p->dsize > sizeof(NbssHdr) + DCE2_SMB_ID_SIZE) ) // DCE2_SMB_ID is u32
    {
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(p->data + sizeof(NbssHdr));
        uint32_t smb_version_id = SmbId((const SmbNtHdr*)smb_hdr);

        if (smb_version_id == DCE2_SMB_ID)
            return DCE2_SMB_VERSION_1;
        else if (smb_version_id == DCE2_SMB2_ID)
            return DCE2_SMB_VERSION_2;
    }

    return DCE2_SMB_VERSION_NULL;
}
