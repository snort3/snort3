//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdint>
#include "dce_smb2.h"

#include "flow/flow_key.h"
#include "stream/stream.h"

#include "dce_smb2_commands.h"

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
    "SMB2_COM_OPLOCK_BREAK" };

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(uint64_t file_id_v,
    uint64_t offset_v) :   file_id(file_id_v), offset(offset_v)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Request tracker created with file_id = 0x%" PRIx64 " offset = %" PRIu64 "\n", file_id,
        offset);
}

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(char* fname_v,
    uint16_t fname_len_v) :   fname(fname_v), fname_len(fname_len_v)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Request tracker created\n");
}

DCE2_Smb2RequestTracker::~DCE2_Smb2RequestTracker()
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Request tracker terminating\n");
    if (fname)
        snort_free(fname);
}

DCE2_Smb2FileTracker::DCE2_Smb2FileTracker(uint64_t file_id_v, DCE2_Smb2TreeTracker* ttr_v,
    DCE2_Smb2SessionTracker* str_v, Flow* flow_v) :   file_id(file_id_v), ttr(ttr_v),
    str(str_v), parent_flow(flow_v), ignore(false), upload(false), multi_channel_file(false)
{
    dce2_smb_stats.v2_total_file_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "File tracker 0x%" PRIx64 " created\n", file_id);
    str->update_cache_size(sizeof(DCE2_Smb2FileTracker));
}

DCE2_Smb2FileTracker::~DCE2_Smb2FileTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "File tracker with file id: 0x%" PRIx64 " tracker terminating\n", file_id);
    auto all_conn_trackers = str->conn_trackers.get_all_entry();
    for ( const auto& h : all_conn_trackers )
    {
        if (h.second->ftracker_tcp)
        {
            if (h.second->ftracker_tcp == this)
            {
                h.second->ftracker_tcp = nullptr;
                h.second->ftracker_local = nullptr;
            }
        }
    }
    if (multi_channel_file)
        dce2_smb_stats.v2_mc_file_transfers++;
    if (co_tracker != nullptr)
    {
        DCE2_CoCleanTracker(co_tracker);
        snort_free((void*)co_tracker);
    }
    str->update_cache_size(-(int)sizeof(DCE2_Smb2FileTracker));
}

DCE2_Smb2TreeTracker::DCE2_Smb2TreeTracker (uint32_t tid_v, uint8_t share_type_v) :
    share_type(share_type_v), tid(tid_v)
{
    dce2_smb_stats.v2_total_tree_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Tree tracker %" PRIu32 " created\n", tid);
}

DCE2_Smb2TreeTracker::~DCE2_Smb2TreeTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Tree tracker %" PRIu32 " terminating\n", tid);
}

DCE2_Smb2SessionTracker::DCE2_Smb2SessionTracker(uint64_t sid) :   conn_trackers(false), session_id(sid),
    encryption_flag(0)
{
    update_cache_size((int)sizeof(DCE2_Smb2SessionTracker));
    dce2_smb_stats.v2_total_session_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Session tracker 0x%" PRIx64 " created\n", session_id);
}

DCE2_Smb2SessionTracker::~DCE2_Smb2SessionTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Session tracker 0x%" PRIx64 " terminating\n", session_id);
    removeSessionFromAllConnection();
    auto all_tree_trackers = tree_trackers.get_all_entry();
    for ( const auto& h : all_tree_trackers )
    {
        removeTtracker(h.first);
    }
    update_cache_size(-(int)sizeof(DCE2_Smb2SessionTracker));
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
                    h.second->ftracker_local = nullptr;
                    break;
                }
            }
        }
        DCE2_Smb2RemoveSidInSsd(h.second, session_id);
    }
}

void DCE2_Smb2SessionTracker::update_cache_size(int size)
{
    DCE2_SmbSessionCacheUpdateSize(size);
}

DCE2_Smb2SsnData::DCE2_Smb2SsnData()
{
    Packet* p = DetectionEngine::get_current_packet();
    memset(&sd, 0, sizeof(DCE2_SsnData));
    memset(&policy, 0, sizeof(DCE2_Policy));
    dialect_index = 0;
    ssn_state_flags = 0;
    ftracker_tcp = nullptr;
    smb_id = 0;
    max_file_depth = FileService::get_max_file_depth();
    max_outstanding_requests = 10;  // Until Negotiate
    flow = p->flow;
    SmbKeyHash hasher;
    flow_key = hasher(*flow->key);
}

DCE2_Smb2SsnData::~DCE2_Smb2SsnData()
{
    for (auto it = session_trackers.cbegin(), next_it = it; it != session_trackers.cend(); it = next_it)
    {
        ++next_it;
        auto sptr = it->second.lock();
        if (sptr)
        {
            if (flow_key)
                sptr->removeConnectionTracker(flow_key); // remove tcp connection from session
                                                         // tracker
            auto ttrs = sptr->tree_trackers.get_all_entry();
            for (const auto& titer: ttrs)
            {
                DCE2_Smb2TreeTracker* ttr = titer.second;
                auto ftrs = ttr->file_trackers.get_all_entry();
                for (const auto& fiter: ftrs)
                {
                    DCE2_Smb2FileTracker* ftr = fiter.second;
                    if (flow == ftr->parent_flow)
                        ftr->parent_flow = nullptr;
                }
            }
        }
    }
}

void DCE2_Smb2SsnData::set_reassembled_data(uint8_t* nb_ptr, uint16_t co_len)
{
    NbssHdr* nb_hdr = (NbssHdr*)nb_ptr;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(NbssHdr));

    uint32_t tid = (ftracker_tcp) ? ftracker_tcp->ttr->get_tid() : 0;
    smb_hdr->smb_tid = alignedNtohl((const uint32_t*)&tid);

    if (DetectionEngine::get_current_packet()->is_from_client())
    {
        Smb2WriteRequestHdr* write = (Smb2WriteRequestHdr*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(Smb2WriteRequestHdr) + co_len;

        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;
        write->structure_size = SMB2_WRITE_REQUEST_STRUC_SIZE;
        nb_hdr->length = htons((uint16_t)nb_len);
        if (ftracker_tcp)
        {
            uint64_t fid = ftracker_tcp->file_id;
            write->fileId_persistent = alignedNtohq(&fid);
            write->fileId_volatile = alignedNtohq(&fid);
        }
        else
            write->fileId_persistent = write->fileId_volatile = 0;
        write->length = alignedNtohs(&co_len);
    }
    else
    {
        Smb2ReadResponseHdr* read = (Smb2ReadResponseHdr*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(Smb2ReadResponseHdr) + co_len;

        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);
        read->structure_size = SMB2_READ_RESPONSE_STRUC_SIZE;
        read->length = alignedNtohs(&co_len);
    }
}

static inline bool DCE2_Smb2FindSidTid(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    const uint32_t tid, const uint32_t mid, DCE2_Smb2SessionTracker** str, DCE2_Smb2TreeTracker** ttr, bool
    lookup_cache = false)
{
    *str = DCE2_Smb2FindSidInSsd(ssd, sid).get();
    if (!*str)
    {
        if (lookup_cache)
            *str = DCE2_Smb2FindElseCreateSid(ssd, sid, false);
    }
    if (!*str)
        return false;

    if (!tid)
        *ttr = ssd->GetTreeTrackerFromMessage(mid);
    else
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
    int16_t structure_size = alignedNtohs((const uint16_t*)smb_data);
    DCE2_Smb2SessionTracker* str = nullptr;
    DCE2_Smb2TreeTracker* ttr = nullptr;
    uint32_t tid = 0;

    uint64_t mid = Smb2Mid(smb_hdr);
    uint64_t sid = Smb2Sid(smb_hdr);
    /* Still process async commands*/
    if (!(alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND))
        tid = Smb2Tid(smb_hdr);

    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
        DetectionEngine::get_current_packet(),
        "%s : mid %" PRIu64 " sid 0x%" PRIx64 " tid %" PRIu32 "\n",
        (command <= SMB2_COM_OPLOCK_BREAK ? smb2_command_string[command] : "unknown"),
        mid, sid, tid);
    switch (command)
    {
    case SMB2_COM_NEGOTIATE:
        if (structure_size == SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE)
        {
            const Smb2NegotiateResponseHdr* neg_resp_hdr = (const
                Smb2NegotiateResponseHdr*)smb_data;
            if (neg_resp_hdr->capabilities & SMB2_GLOBAL_CAP_MULTI_CHANNEL)
            {
                //total multichannel sessions
                dce2_smb_stats.total_mc_sessions++;
            }
        }
        break;
    case SMB2_COM_CREATE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_crt++;
        DCE2_Smb2Create(ssd, smb_hdr, smb_data, end, mid, sid, tid);
        break;
    case SMB2_COM_READ:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_read++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr, true))
        {
            dce2_smb_stats.v2_read_ignored++;
            return;
        }

        DCE2_Smb2Read(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_WRITE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_wrt++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr, true))
        {
            dce2_smb_stats.v2_wrt_ignored++;
            return;
        }

        DCE2_Smb2Write(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_SET_INFO:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_setinfo++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_stinf_ignored++;
            return;
        }

        DCE2_Smb2SetInfo(ssd, smb_hdr, smb_data, end, ttr);
        break;
    case SMB2_COM_CLOSE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_cls++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_cls_ignored++;
            return;
        }

        DCE2_Smb2CloseCmd(ssd, smb_hdr, smb_data, end, ttr, str, mid);
        break;
    case SMB2_COM_TREE_CONNECT:
        dce2_smb_stats.v2_tree_cnct++;
        // This will always return session tracker
        str = DCE2_Smb2FindElseCreateSid(ssd, sid, true);
        if (str)
        {
            DCE2_Smb2TreeConnect(ssd, smb_hdr, smb_data, end, str, tid);
        }
        break;
    case SMB2_COM_TREE_DISCONNECT:
        dce2_smb_stats.v2_tree_discn++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_tree_discn_ignored++;
            return;
        }
        DCE2_Smb2TreeDisconnect(ssd, smb_data, end);
        break;
    case SMB2_COM_SESSION_SETUP:
        dce2_smb_stats.v2_setup++;
        DCE2_Smb2Setup(ssd, smb_hdr, sid, smb_data, end);
        break;
    case SMB2_COM_LOGOFF:
        dce2_smb_stats.v2_logoff++;
        DCE2_Smb2Logoff(ssd, smb_data, sid);
        break;
    case SMB2_COM_IOCTL:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_ioctl_ignored++;
            return;
        }
        else if (SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_ioctl++;
            DCE2_Smb2IoctlCommand(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        }
        else
        {
            dce2_smb_stats.v2_ioctl_ignored++;
            return;
        }
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
    // Process the header
    if (p->is_pdu_start())
    {
        // Check header length
        if (data_len < sizeof(NbssHdr) + SMB2_HEADER_LENGTH)
        {
            dce2_smb_stats.v2_hdr_err++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
                "Header error with data length %d\n",data_len);
            return;
        }
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(data_ptr + sizeof(NbssHdr));
        const Smb2TransformHdr* smb_trans_hdr = (const Smb2TransformHdr*)(data_ptr +
            sizeof(NbssHdr));
        uint32_t smb_proto_id = SmbTransformId(smb_trans_hdr);
        uint64_t sid = smb_trans_hdr->session_id;
        if (smb_proto_id == DCE2_SMB2_TRANS_ID)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                p, "Encrypted header is received \n");
            DCE2_Smb2SessionTracker* session = DCE2_Smb2FindElseCreateSid(ssd, sid);
            if (session)
            {
                session->set_encryption_flag(true);
            }
        }
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
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    p, "bad next command offset\n");
                dce2_smb_stats.v2_bad_next_cmd_offset++;
                return;
            }
            if (next_command_offset)
            {
                // Check if adding next_command_offset would cause integer overflow
                if (next_command_offset > SIZE_MAX - (uintptr_t)((const uint8_t*)smb_hdr))
                {
                    dce_alert(GID_DCE2, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET,
                        (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
                    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                        p, "integer overflow in next command offset\n");
                    dce2_smb_stats.v2_bad_next_cmd_offset++;
                    return;
                }
                smb_hdr = (const Smb2Hdr*)((const uint8_t*)smb_hdr + next_command_offset);
                compound_request_index++;
            }

            if (compound_request_index > DCE2_ScSmbMaxCompound((dce2SmbProtoConf*)ssd->sd.config))
            {
                dce2_smb_stats.v2_cmpnd_req_lt_crossed++;
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    p, "compound req limit reached %" PRIu8 "\n",
                    compound_request_index);
                return;
            }
        }
        while (next_command_offset and smb_hdr);
    }
    else if ( ssd->ftracker_tcp and ssd->ftracker_local and (ssd->ftracker_local->smb2_pdu_state ==
        DCE2_SMB_PDU_STATE__RAW_DATA))
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            p, "raw data file_name_hash %" PRIu64 " fid 0x%" PRIx64 " dir %s\n",
            ssd->ftracker_tcp->file_name_hash, ssd->ftracker_tcp->file_id,
            ssd->ftracker_tcp->upload ? "upload" : "download");

        if (!DCE2_Smb2ProcessFileData(ssd, data_ptr, data_len))
            return;
    }
}

// Check whether the packet is smb2
DCE2_SmbVersion DCE2_Smb2Version(const Packet* p)
{
    // Only check reassembled SMB2 packet
    if ( p->has_paf_payload() and
        (p->dsize > sizeof(NbssHdr) + DCE2_SMB_ID_SIZE) )     // DCE2_SMB_ID is u32
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
