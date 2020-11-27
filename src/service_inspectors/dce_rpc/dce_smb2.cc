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
#include "flow/flow_key.h"
#include "main/snort_debug.h"

using namespace snort;

const char* smb2_command_string[SMB2_COM_MAX] = {
    "SMB2_COM_NEGOTIATE",
    "SMB2_COM_SESSION_SETUP",
    "SMB2_COM_LOGOFF",
    "SMB2_COM_TREE_CONNECT",
    "SMB2_COM_TREE_DISCONNECT",
    "SMB2_COM_CREATE",
    "SMB2_COM_CLOSE",
    "SMB2_COM_FLUSH",
    "SMB2_COM_READ",
    "SMB2_COM_WRITE",
    "SMB2_COM_LOCK",
    "SMB2_COM_IOCTL",
    "SMB2_COM_CANCEL",
    "SMB2_COM_ECHO",
    "SMB2_COM_QUERY_DIRECTORY",
    "SMB2_COM_CHANGE_NOTIFY",
    "SMB2_COM_QUERY_INFO",
    "SMB2_COM_SET_INFO",
    "SMB2_COM_OPLOCK_BREAK"};

static inline SmbFlowKey get_flow_key(void)
{
    SmbFlowKey key;
    const FlowKey* flow_key = DetectionEngine::get_current_packet()->flow->key;

    key.ip_l[0] = flow_key->ip_l[0];
    key.ip_l[1] = flow_key->ip_l[1];
    key.ip_l[2] = flow_key->ip_l[2];
    key.ip_l[3] = flow_key->ip_l[3];
    key.ip_h[0] = flow_key->ip_h[0];
    key.ip_h[1] = flow_key->ip_h[1];
    key.ip_h[2] = flow_key->ip_h[2];
    key.ip_h[3] = flow_key->ip_h[3];
    key.mplsLabel = flow_key->mplsLabel;
    key.port_l = flow_key->port_l;
    key.port_h = flow_key->port_h;
    key.group_l = flow_key->group_l;
    key.group_h = flow_key->group_h;
    key.vlan_tag = flow_key->vlan_tag;
    key.addressSpaceId = flow_key->addressSpaceId;
    key.ip_protocol = flow_key->ip_protocol;
    key.pkt_type = (uint8_t)flow_key->pkt_type;
    key.version = flow_key->version;
    key.padding = 0;

    return key;
}

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(uint64_t file_id_v,
    uint64_t offset_v) : file_id(file_id_v), offset(offset_v)
{
    debug_logf(dce_smb_trace, nullptr, "request tracker created\n");
    memory::MemoryCap::update_allocations(sizeof(*this));
}

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(char* fname_v,
    uint16_t fname_len_v) : fname(fname_v), fname_len(fname_len_v)
{
    debug_logf(dce_smb_trace, nullptr, "request tracker created\n");
    memory::MemoryCap::update_allocations(sizeof(*this));
}

DCE2_Smb2RequestTracker::~DCE2_Smb2RequestTracker()
{
    debug_logf(dce_smb_trace, nullptr, "request tracker terminating\n");
    if (!file_id and fname)
        snort_free(fname);
    memory::MemoryCap::update_deallocations(sizeof(*this));
}

DCE2_Smb2FileTracker::DCE2_Smb2FileTracker(uint64_t file_id_v, DCE2_Smb2TreeTracker* ttr_v,
    DCE2_Smb2SessionTracker* str_v, Flow* flow_v) : file_id(file_id_v), ttr(ttr_v),
    str(str_v), flow(flow_v)
{
    debug_logf(dce_smb_trace, nullptr, "file tracker %" PRIu64 " created\n", file_id);
    memory::MemoryCap::update_allocations(sizeof(*this));
}

DCE2_Smb2FileTracker::~DCE2_Smb2FileTracker(void)
{
    debug_logf(dce_smb_trace, nullptr,
        "file tracker %" PRIu64 " file name hash %" PRIu64 " terminating\n",
         file_id, file_name_hash);

    FileFlows* file_flows = FileFlows::get_file_flows(flow, false);
    if (file_flows)
    {
        file_flows->remove_processed_file_context(file_name_hash, file_id);
    }

    if (file_name)
        snort_free((void*)file_name);

    memory::MemoryCap::update_deallocations(sizeof(*this));
}

DCE2_Smb2TreeTracker::DCE2_Smb2TreeTracker (uint32_t tid_v, uint8_t share_type_v) :
    share_type(share_type_v), tid(tid_v)
{
    debug_logf(dce_smb_trace, nullptr, "tree tracker %" PRIu32 " created\n", tid);
    memory::MemoryCap::update_allocations(sizeof(*this));
}

DCE2_Smb2TreeTracker::~DCE2_Smb2TreeTracker(void)
{
    debug_logf(dce_smb_trace, nullptr, "tree tracker %" PRIu32 " terminating\n", tid);

    auto all_req_trackers = req_trackers.get_all_entry();
    if (all_req_trackers.size())
    {
        debug_logf(dce_smb_trace, nullptr, "cleanup pending requests for below MIDs:\n");
        for ( auto& h : all_req_trackers )
        {
            debug_logf(dce_smb_trace, nullptr, "mid %" PRIu64 "\n", h.first);
            removeRtracker(h.first);
        }
    }
    memory::MemoryCap::update_deallocations(sizeof(*this));
}

DCE2_Smb2SessionTracker::DCE2_Smb2SessionTracker()
{
    debug_logf(dce_smb_trace, nullptr, "session tracker %" PRIu64 " created\n", session_id);
    memory::MemoryCap::update_allocations(sizeof(*this));
}

DCE2_Smb2SessionTracker::~DCE2_Smb2SessionTracker(void)
{
    debug_logf(dce_smb_trace, nullptr, "session tracker %" PRIu64 " terminating\n", session_id);
    removeSessionFromAllConnection();
    memory::MemoryCap::update_deallocations(sizeof(*this));
}

void DCE2_Smb2SessionTracker::removeSessionFromAllConnection()
{
    auto all_conn_trackers = conn_trackers.get_all_entry();
    auto all_tree_trackers = tree_trackers.get_all_entry();
    for ( auto& h : all_conn_trackers )
    {
        if (h.second->ftracker_tcp)
        {
            for (auto& t : all_tree_trackers)
            {
                DCE2_Smb2FileTracker* ftr = t.second->findFtracker(
                    h.second->ftracker_tcp->file_id);
                if (ftr and ftr == h.second->ftracker_tcp)
                {
                    h.second->ftracker_tcp = nullptr;
                    break;
                }
            }
        }
        DCE2_Smb2RemoveSidInSsd(h.second, session_id);
    }
}

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

    debug_logf(dce_smb_trace, DetectionEngine::get_current_packet(),
        "%s : mid %" PRIu64 " sid %" PRIu64 " tid %" PRIu32 "\n",
        (command <= SMB2_COM_OPLOCK_BREAK ? smb2_command_string[command] : "unknown"),
        mid, sid, tid);
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

        DCE2_Smb2CloseCmd(ssd, smb_hdr, smb_data, end, ttr, str);
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
        debug_logf(dce_smb_trace, p, "Header error with data length %d\n",data_len);
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
                debug_logf(dce_smb_trace, p, "bad next command offset\n");
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
                debug_logf(dce_smb_trace, p, "compound req limit reached %" PRIu8 "\n",
                    compound_request_index);
                return;
            }
        }
        while (next_command_offset and smb_hdr);
    }
    else if ( ssd->ftracker_tcp and (ssd->ftracker_tcp->smb2_pdu_state ==
        DCE2_SMB_PDU_STATE__RAW_DATA))
    {
        debug_logf(dce_smb_trace, p,
            "raw data file_name_hash %" PRIu64 " fid %" PRIu64 " dir %s\n",
            ssd->ftracker_tcp->file_name_hash, ssd->ftracker_tcp->file_id,
            ssd->ftracker_tcp->upload ? "upload" : "download");

        if (!DCE2_Smb2ProcessFileData(ssd, data_ptr, data_len))
            return;
        ssd->ftracker_tcp->file_offset += data_len;
    }
}

DCE2_Ret DCE2_Smb2InitData(DCE2_Smb2SsnData* ssd)
{
    memset(&ssd->sd, 0, sizeof(DCE2_SsnData));
    ssd->session_trackers.SetDoNotFree();
    memset(&ssd->policy, 0, sizeof(DCE2_Policy));
    ssd->dialect_index = 0;
    ssd->ssn_state_flags = 0;
    ssd->ftracker_tcp = nullptr;
    ssd->max_file_depth = FileService::get_max_file_depth();
    ssd->flow_key = get_flow_key();
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

