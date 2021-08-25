//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_util.h"
#include "flow/flow_key.h"
#include "stream/stream.h"

#include "dce_smb2_file.h"
#include "dce_smb2_session.h"
#include "dce_smb2_session_cache.h"
#include "dce_smb2_tree.h"

using namespace snort;

Dce2Smb2SessionCache smb2_session_cache(SMB_DEFAULT_MEMCAP);

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
    "SMB2_COM_OPLOCK_BREAK"
};

static inline uint64_t Smb2Sid(const Smb2Hdr* hdr)
{
    return alignedNtohq(&(hdr->session_id));
}

static inline bool Smb2Error(const Smb2Hdr* hdr)
{
    return (SMB_NT_STATUS_SEVERITY__ERROR == (uint8_t)(hdr->status >> 30));
}

uint32_t get_smb2_flow_key(const FlowKey* flow_key)
{
    Smb2FlowKey key;

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

    Smb2KeyHash hasher;
    return hasher(key);
}

//Dce2Smb2SessionData member functions

Dce2Smb2SessionData::Dce2Smb2SessionData(const Packet* p,
    const dce2SmbProtoConf* proto) : Dce2SmbSessionData(p, proto)
{
    tcp_file_tracker = nullptr;
    flow_key = get_smb2_flow_key(tcp_flow->key);
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p, "smb2 session created\n");
    memory::MemoryCap::update_allocations(sizeof(*this));
}

Dce2Smb2SessionData::~Dce2Smb2SessionData()
{
    session_data_mutex.lock();
    for (auto it_session : connected_sessions)
    {
        it_session.second->detach_flow(flow_key);
    }
    session_data_mutex.unlock();
    memory::MemoryCap::update_deallocations(sizeof(*this));
}

void Dce2Smb2SessionData::reset_matching_tcp_file_tracker(
    Dce2Smb2FileTracker* file_tracker)
{
    std::lock_guard<std::mutex> guard(tcp_file_tracker_mutex);
    if (tcp_file_tracker == file_tracker)
        tcp_file_tracker = nullptr;
}

Smb2SessionKey Dce2Smb2SessionData::get_session_key(uint64_t session_id)
{
    Smb2SessionKey key;
    Flow* flow = DetectionEngine::get_current_packet()->flow;
    memcpy(key.cip, flow->client_ip.get_ip6_ptr(), 4*sizeof(uint32_t));
    memcpy(key.sip, flow->server_ip.get_ip6_ptr(), 4*sizeof(uint32_t));
    key.sid = session_id;
    key.cgroup = flow->client_group;
    key.sgroup = flow->server_group;
    key.asid = flow->key->addressSpaceId;
    key.padding = 0;
    return key;
}

Dce2Smb2SessionTrackerPtr Dce2Smb2SessionData::find_session(uint64_t session_id)
{
    std::lock_guard<std::mutex> guard(session_data_mutex);
    auto it_session = connected_sessions.find(session_id);

    if (it_session != connected_sessions.end())
    {
        Dce2Smb2SessionTrackerPtr session = it_session->second;
        //we already have the session, but call find to update the LRU
        smb2_session_cache.find_session(session->get_key(), this);
        return session;
    }
    else
    {
        Dce2Smb2SessionTrackerPtr session = smb2_session_cache.find_session(
            get_session_key(session_id), this);
        if (session)
            connected_sessions.insert(std::make_pair(session_id,session));
        return session;
    }
}

// Caller must ensure that the session is not already present in flow
Dce2Smb2SessionTrackerPtr Dce2Smb2SessionData::create_session(uint64_t session_id)
{
    Smb2SessionKey session_key = get_session_key(session_id);
    std::lock_guard<std::mutex> guard(session_data_mutex);
    Dce2Smb2SessionTrackerPtr session = smb2_session_cache.find_else_create_session(session_key, this);
    connected_sessions.insert(std::make_pair(session_id, session));
    return session;
}

void Dce2Smb2SessionData::remove_session(uint64_t session_id, bool sync)
{
    if (sync) session_data_mutex.lock();
    connected_sessions.erase(session_id);
    if (sync) session_data_mutex.unlock();
}

void Dce2Smb2SessionData::process_command(const Smb2Hdr* smb_hdr,
    const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_hdr + SMB2_HEADER_LENGTH;
    uint16_t structure_size = alignedNtohs((const uint16_t*)smb_data);

// Macro and shorthand to save some repetitive code
// Should only be used in this function
#define SMB2_COMMAND_TYPE(cmd, type) \
    (structure_size == SMB2_ ## cmd ## _ ## type ## _STRUC_SIZE)

#define SMB2_GET_COMMAND_TYPE(cmd) \
    (SMB2_COMMAND_TYPE(ERROR,RESPONSE) and Smb2Error(smb_hdr)) ? \
    SMB2_CMD_TYPE_ERROR_RESPONSE : (SMB2_COMMAND_TYPE(cmd, REQUEST) ? \
    SMB2_CMD_TYPE_REQUEST : (SMB2_COMMAND_TYPE(cmd, RESPONSE) ? \
    SMB2_CMD_TYPE_RESPONSE : SMB2_CMD_TYPE_INVALID))

#define SMB2_HANDLE_HEADER_ERROR(cmd, type, counter) \
    { \
        if (smb_data + SMB2_ ## cmd ## _ ## type ## _STRUC_SIZE - 1 > end) \
        { \
            dce2_smb_stats.v2_ ## counter ## _hdr_err++; \
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, GET_CURRENT_PACKET, \
                "%s : smb data beyond end detected\n", \
                smb2_command_string[command]); \
            return; \
        } \
    }

#define SMB2_HANDLE_ERROR_RESPONSE(counter) \
    { \
        if (SMB2_COMMAND_TYPE(ERROR, RESPONSE) and Smb2Error(smb_hdr)) \
        { \
            dce2_smb_stats.v2_ ## counter ## _err_resp++; \
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, GET_CURRENT_PACKET, "%s_RESP: error\n", \
                smb2_command_string[command]); \
            return; \
        } \
    }

#define SMB2_HANDLE_INVALID_STRUC_SIZE(counter) \
    { \
        dce2_smb_stats.v2_ ## counter ## _inv_str_sz++; \
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL \
	    , GET_CURRENT_PACKET, "%s: invalid struct size\n", \
            smb2_command_string[command]); \
        return; \
    }

    uint16_t command = alignedNtohs(&(smb_hdr->command));
    uint64_t session_id = Smb2Sid(smb_hdr);
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
        "%s : flow %" PRIu32 " mid %" PRIu64 " sid %" PRIu64 " tid %" PRIu32 "\n",
        (command < SMB2_COM_MAX ? smb2_command_string[command] : "unknown"),
        flow_key, Smb2Mid(smb_hdr), session_id, Smb2Tid(smb_hdr));
    // Try to find the session.
    // The case when session is not available will be handled per command.
    Dce2Smb2SessionTrackerPtr session = find_session(session_id);

    switch (command)
    {
    //commands processed by flow
    case SMB2_COM_NEGOTIATE:
        if (SMB2_COMMAND_TYPE(NEGOTIATE, RESPONSE))
        {
            const Smb2NegotiateResponseHdr* neg_resp_hdr = (const Smb2NegotiateResponseHdr*)smb_data;
            if (neg_resp_hdr->capabilities & SMB2_GLOBAL_CAP_MULTI_CHANNEL)
            {
                Packet* p = DetectionEngine::get_current_packet();
                Dce2SmbFlowData* fd = create_expected_smb_flow_data(p);
                if (fd)
                {
                    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                        "Requesting for expected smb flow\n");
                    int result = Stream::set_snort_protocol_id_expected(p, PktType::TCP,
                        IpProtocol::TCP, p->ptrs.ip_api.get_dst() , 0 ,p->ptrs.ip_api.get_src(),
                        p->flow->server_port , snort_protocol_id_smb, fd, false, true);
                
                    if (result < 0)
                    {
                        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                            "Failed to create expected smb flow\n");
                        delete fd;
                    }
                }
                else
                {
                    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                        "fd is null in negotiate , failed to create pinhole\n");
                }
            }
        }
        break;
    case SMB2_COM_SESSION_SETUP:
        dce2_smb_stats.v2_setup++;
        SMB2_HANDLE_ERROR_RESPONSE(setup)
        if (SMB2_COMMAND_TYPE(SETUP, RESPONSE))
        {
            SMB2_HANDLE_HEADER_ERROR(SETUP, RESPONSE, setup_resp)
            if (!session)
                create_session(session_id);
        }
        else if (!SMB2_COMMAND_TYPE(SETUP, REQUEST))
            SMB2_HANDLE_INVALID_STRUC_SIZE(setup)
        break;

    case SMB2_COM_LOGOFF:
        dce2_smb_stats.v2_logoff++;
        if (SMB2_COMMAND_TYPE(LOGOFF, REQUEST))
        {
            session_data_mutex.lock();
            smb2_session_cache.remove(get_session_key(session_id));
            session_data_mutex.unlock();
        }
        else
            SMB2_HANDLE_INVALID_STRUC_SIZE(logoff)
        break;
    //commands processed by session
    case SMB2_COM_TREE_CONNECT:
        dce2_smb_stats.v2_tree_cnct++;
        SMB2_HANDLE_ERROR_RESPONSE(tree_cnct)
        if (SMB2_COMMAND_TYPE(TREE_CONNECT, RESPONSE))
        {
            SMB2_HANDLE_HEADER_ERROR(TREE_CONNECT, RESPONSE, tree_cnct_resp)
            if (!session)
                session = create_session(session_id);
            session->process(command, SMB2_CMD_TYPE_RESPONSE, smb_hdr, end, flow_key);
        }
        else if (!SMB2_COMMAND_TYPE(TREE_CONNECT,REQUEST))
            SMB2_HANDLE_INVALID_STRUC_SIZE(tree_cnct)
        break;

    case SMB2_COM_TREE_DISCONNECT:
        dce2_smb_stats.v2_tree_discn++;

        if (session)
        {
            if (SMB2_COMMAND_TYPE(TREE_DISCONNECT, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(TREE_DISCONNECT, REQUEST, tree_discn_req)
                session->process(command, SMB2_CMD_TYPE_REQUEST, smb_hdr, end, flow_key);
            }
            else
            {
                SMB2_HANDLE_INVALID_STRUC_SIZE(tree_discn)
            }
        }
        else
            dce2_smb_stats.v2_session_ignored++;
        break;
    //commands processed by tree
    case SMB2_COM_CREATE:
    {
        dce2_smb_stats.v2_crt++;
        uint8_t command_type = SMB2_GET_COMMAND_TYPE(CREATE);
        if (SMB2_CMD_TYPE_INVALID == command_type)
            SMB2_HANDLE_INVALID_STRUC_SIZE(crt)
        else if (SMB2_COMMAND_TYPE(CREATE, REQUEST))
            SMB2_HANDLE_HEADER_ERROR(CREATE, REQUEST, crt_req)
        else if (SMB2_COMMAND_TYPE(CREATE, RESPONSE))
            SMB2_HANDLE_HEADER_ERROR(CREATE, RESPONSE, crt_resp)

        if (!session)
            session = create_session(session_id);
        session->process(command, command_type, smb_hdr, end, flow_key);
    }
        break;

    case SMB2_COM_CLOSE:
        dce2_smb_stats.v2_cls++;
        SMB2_HANDLE_ERROR_RESPONSE(cls)
        if (session)
        {
            if (SMB2_COMMAND_TYPE(CLOSE, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(CLOSE, REQUEST, cls_req)
                session->process(command, SMB2_CMD_TYPE_REQUEST, smb_hdr, end, flow_key);
            }
            else if (!SMB2_COMMAND_TYPE(CLOSE, RESPONSE))
            {
                SMB2_HANDLE_INVALID_STRUC_SIZE(cls)
            }
        }
        else
            dce2_smb_stats.v2_session_ignored++;
        break;

    case SMB2_COM_SET_INFO:
        dce2_smb_stats.v2_setinfo++;
        SMB2_HANDLE_ERROR_RESPONSE(stinf)
        if (session)
        {
            if (SMB2_COMMAND_TYPE(SET_INFO, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(SET_INFO, REQUEST, stinf_req)
                session->process(command, SMB2_CMD_TYPE_REQUEST, smb_hdr, end, flow_key);
            }
            else if (!SMB2_COMMAND_TYPE(SET_INFO, RESPONSE))
            {
                SMB2_HANDLE_INVALID_STRUC_SIZE(stinf)
            }
        }
        else
            dce2_smb_stats.v2_session_ignored++;
        break;

    case SMB2_COM_READ:
        dce2_smb_stats.v2_read++;
        if (session)
        {
            uint8_t command_type;
            if (SMB2_COMMAND_TYPE(ERROR, RESPONSE) and Smb2Error(smb_hdr))
                command_type = SMB2_CMD_TYPE_ERROR_RESPONSE;
            else if (SMB2_COMMAND_TYPE(READ, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(READ, REQUEST, read_req)
                command_type = SMB2_CMD_TYPE_REQUEST;
            }
            else if (SMB2_COMMAND_TYPE(READ, RESPONSE))
            {
                SMB2_HANDLE_HEADER_ERROR(READ, RESPONSE, read_resp)
                command_type = SMB2_CMD_TYPE_RESPONSE;
            }
            else
                SMB2_HANDLE_INVALID_STRUC_SIZE(read)
            session->process(command, command_type, smb_hdr, end, flow_key);
        }
        else
            dce2_smb_stats.v2_session_ignored++;
        break;

    case SMB2_COM_WRITE:
        dce2_smb_stats.v2_wrt++;
        if (session)
        {
            uint8_t command_type;
            if (SMB2_COMMAND_TYPE(ERROR, RESPONSE) and Smb2Error(smb_hdr))
                command_type = SMB2_CMD_TYPE_ERROR_RESPONSE;
            else if (SMB2_COMMAND_TYPE(WRITE, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(WRITE, REQUEST, wrt_req)
                command_type = SMB2_CMD_TYPE_REQUEST;
            }
            else if (SMB2_COMMAND_TYPE(WRITE, RESPONSE))
            {
                SMB2_HANDLE_HEADER_ERROR(WRITE, RESPONSE, wrt_resp)
                command_type = SMB2_CMD_TYPE_RESPONSE;
            }
            else
                SMB2_HANDLE_INVALID_STRUC_SIZE(wrt)
            session->process(command, command_type, smb_hdr, end, flow_key);
        }
        else
            dce2_smb_stats.v2_session_ignored++;
        break;
    case SMB2_COM_IOCTL:
        if (session)
        {
            if (SMB2_COMMAND_TYPE(IOCTL, REQUEST))
            {
                SMB2_HANDLE_HEADER_ERROR(IOCTL, REQUEST, ioctl_req)
                session->process(command, SMB2_CMD_TYPE_REQUEST, smb_hdr, end, flow_key);
            }
            else if ( SMB2_COMMAND_TYPE(IOCTL, RESPONSE))
            {
                SMB2_HANDLE_HEADER_ERROR(IOCTL, RESPONSE, ioctl_resp)
                session->process(command, SMB2_CMD_TYPE_RESPONSE, smb_hdr, end, flow_key);
            }
            else
            {
                SMB2_HANDLE_INVALID_STRUC_SIZE(ioctl)
            }
        }
        break;
    default:
        dce2_smb_stats.v2_msgs_uninspected++;
        break;
    }
}

// This is the main entry point for SMB2 processing.
void Dce2Smb2SessionData::process()
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
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, 
                p, "Header error with data length %d\n",data_len);
            dce2_smb_stats.v2_hdr_err++;
            return;
        }
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
            process_command(smb_hdr, data_ptr +  data_len);
            // In case of message compounding, find the offset of the next smb command
            next_command_offset = alignedNtohl(&(smb_hdr->next_command));
            if (next_command_offset + (const uint8_t*)smb_hdr > (data_ptr + data_len))
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET,
                    (dce2CommonStats*)&dce2_smb_stats, sd);
		        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, 
		        TRACE_ERROR_LEVEL, p, "bad next command offset\n");
                dce2_smb_stats.v2_bad_next_cmd_offset++;
                return;
            }
            if (next_command_offset)
            {
                smb_hdr = (const Smb2Hdr*)((const uint8_t*)smb_hdr + next_command_offset);
                compound_request_index++;
            }

            if (compound_request_index > get_smb_max_compound())
            {
                dce2_smb_stats.v2_cmpnd_req_lt_crossed++;
		        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, 
		            TRACE_INFO_LEVEL, p, "compound request limit"
                    " reached %" PRIu8 "\n",compound_request_index);
                return;
            }
        }
        while (next_command_offset and smb_hdr);
    }
    else
    {
        tcp_file_tracker_mutex.lock();
        if ( tcp_file_tracker and tcp_file_tracker->accepting_raw_data_from(flow_key))
        {
            SMB_DEBUG(dce_smb_trace,DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p, "processing raw data for file id %" PRIu64 "\n",
                tcp_file_tracker->get_file_id());
            tcp_file_tracker->process_data(flow_key, data_ptr, data_len);
            tcp_file_tracker->stop_accepting_raw_data_from(flow_key);
        }
        else
        {
            SMB_DEBUG(dce_smb_trace,DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p, "not processing raw data\n");
        }
        tcp_file_tracker_mutex.unlock();
    }
}

void Dce2Smb2SessionData::set_reassembled_data(uint8_t* nb_ptr, uint16_t co_len)
{
    NbssHdr* nb_hdr = (NbssHdr*)nb_ptr;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(NbssHdr));

    tcp_file_tracker_mutex.lock();
    uint32_t tid = (tcp_file_tracker) ? tcp_file_tracker->get_parent()->get_tree_id() : 0;
    tcp_file_tracker_mutex.unlock();

    smb_hdr->smb_tid = alignedNtohl((const uint32_t*)&tid);

    if (DetectionEngine::get_current_packet()->is_from_client())
    {
        Smb2WriteRequestHdr* write = (Smb2WriteRequestHdr*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(Smb2WriteRequestHdr) + co_len;

        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;
        write->structure_size = SMB2_WRITE_REQUEST_STRUC_SIZE;
        nb_hdr->length = htons((uint16_t)nb_len);

        tcp_file_tracker_mutex.lock();
        if (tcp_file_tracker)
        {
            uint64_t fid = tcp_file_tracker->get_file_id();
            write->fileId_persistent = alignedNtohq(&fid);
            write->fileId_volatile = alignedNtohq(&fid);
        }
        else
            write->fileId_persistent = write->fileId_volatile = 0;
        tcp_file_tracker_mutex.unlock();

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
