//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb_common.cc author Dipta Pandit <dipandit@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb_common.h"

#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "memory/memory_cap.h"

#include "dce_smb1.h"
#include "dce_smb2.h"

using namespace snort;

THREAD_LOCAL dce2SmbStats dce2_smb_stats;
THREAD_LOCAL ProfileStats dce2_smb_pstat_main;

//Dce2SmbFlowData members

unsigned Dce2SmbFlowData::inspector_id = 0;

Dce2SmbFlowData::Dce2SmbFlowData(Dce2SmbSessionData* ssd_v) : FlowData(inspector_id)
{
    dce2_smb_stats.concurrent_sessions++;
    if (dce2_smb_stats.max_concurrent_sessions < dce2_smb_stats.concurrent_sessions)
        dce2_smb_stats.max_concurrent_sessions = dce2_smb_stats.concurrent_sessions;
    ssd = ssd_v;
}

Dce2SmbSessionData* Dce2SmbFlowData::upgrade(const Packet* p)
{
    dce2SmbProtoConf* config =
        (dce2SmbProtoConf*)ssd->get_dce2_session_data()->config;
    delete ssd;
    ssd = new Dce2Smb2SessionData(p, config);
    return ssd;
}

void Dce2SmbFlowData::handle_retransmit(Packet* p)
{
    FilePosition position = get_file_position(p);
    if (!(SNORT_FILE_FULL == position or SNORT_FILE_END == position))
        return;
    FileContext* context = get_smb_file_context(p);
    FileVerdict verdict = context ? context->verdict : FILE_VERDICT_UNKNOWN;
    ssd->handle_retransmit(position, verdict);
}

Dce2SmbFlowData::~Dce2SmbFlowData()
{
    if (ssd)
        delete ssd;
    assert(dce2_smb_stats.concurrent_sessions > 0);
    dce2_smb_stats.concurrent_sessions--;
}

//Dce2SmbSessionData members

Dce2SmbSessionData::Dce2SmbSessionData(const Packet* p,
    const dce2SmbProtoConf* config)
{
    sd = { };
    policy = { };
    tcp_flow = p->flow;
    DCE2_ResetRopts(&sd, p);
    sd.trans = DCE2_TRANS_TYPE__SMB;
    sd.server_policy = config->common.policy;
    sd.client_policy = DCE2_POLICY__WINXP;
    sd.config = (void*)config;
    dialect_index = DCE2_SENTINEL;
    max_file_depth = FileService::get_max_file_depth();
    dce2_smb_stats.smb_sessions++;
}

//Helper functions

static inline DCE2_SmbVersion get_smb_version(const Packet* p)
{
    // Only check reassembled SMB2 packet
    if ( p->has_paf_payload() and (p->dsize > sizeof(NbssHdr) + DCE2_SMB_ID_SIZE))
    {
        const SmbNtHdr* smb_hdr = (const SmbNtHdr*)(p->data + sizeof(NbssHdr));
        uint32_t smb_version_id = SmbId(smb_hdr);

        if (smb_version_id == DCE2_SMB_ID)
            return DCE2_SMB_VERSION_1;
        else if (smb_version_id == DCE2_SMB2_ID)
            return DCE2_SMB_VERSION_2;
    }

    return DCE2_SMB_VERSION_NULL;
}

Dce2SmbFlowData* create_expected_smb_flow_data(const Packet* p)
{
    DCE2_SmbVersion smb_version = get_smb_version(p);
    if (DCE2_SMB_VERSION_2 == smb_version)
    {
        return new Dce2SmbFlowData();
    }
    return nullptr;
}

Dce2SmbSessionData* create_smb_session_data(Dce2SmbFlowData* flow_data, const Packet* p,
    dce2SmbProtoConf* config)
{
    DCE2_SmbVersion smb_version = get_smb_version(p);
    if (DCE2_SMB_VERSION_2 != smb_version)
        return nullptr;
    Dce2SmbSessionData* ssd = (Dce2SmbSessionData*)new Dce2Smb2SessionData(p, config);
    flow_data->update_smb_session_data(ssd);
    return ssd;
}

Dce2SmbSessionData* create_new_smb_session(const Packet* p,
    dce2SmbProtoConf* config)
{
    DCE2_SmbVersion smb_version = get_smb_version(p);

    if (DCE2_SMB_VERSION_NULL == smb_version)
        return nullptr;

    Dce2SmbSessionData* ssd = (DCE2_SMB_VERSION_1 == smb_version) ?
        (Dce2SmbSessionData*)new Dce2Smb1SessionData(p, config) :
        (Dce2SmbSessionData*)new Dce2Smb2SessionData(p, config);

    Dce2SmbFlowData* flow_data = new Dce2SmbFlowData(ssd);
    p->flow->set_flow_data(flow_data);

    return ssd;
}

DCE2_SsnData* get_dce2_session_data(snort::Flow* flow)
{
    Dce2SmbFlowData* fd = (Dce2SmbFlowData*)flow->get_flow_data(Dce2SmbFlowData::inspector_id);
    return fd ? fd->get_smb_session_data() ? fd->get_smb_session_data()->get_dce2_session_data() :
        nullptr : nullptr;
}

inline FileContext* get_smb_file_context(const Packet* p)
{
    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
    if (file_flows)
    {
        std::lock_guard<std::mutex> guard(file_flows->file_flow_context_mutex);
        return file_flows->get_current_file_context();
    }
    else
        return nullptr;
}

FileContext* get_smb_file_context(Flow* flow, uint64_t file_id,
    uint64_t multi_file_processing_id, bool to_create)
{
    if (!flow)
    {
        dce2_smb_stats.v2_inv_file_ctx_err++;
        return nullptr;
    }
    FileFlows* file_flows = FileFlows::get_file_flows(flow);

    if ( !file_flows )
    {
        dce2_smb_stats.v2_inv_file_ctx_err++;
        return nullptr;
    }

    std::lock_guard<std::mutex> guard(file_flows->file_flow_context_mutex);
    return file_flows->get_file_context(file_id, to_create, multi_file_processing_id);
}

char* get_smb_file_name(const uint8_t* data, uint32_t data_len, bool unicode,
    uint16_t* file_name_len)
{
    const uint8_t inc = unicode ? 2 : 1;
    if (data_len < inc)
        return nullptr;

    const uint32_t max_len =  unicode ? data_len - 1 : data_len;
    // Move forward.  Don't know if the end of data is actually
    // the end of the string.
    uint32_t i;
    for (i = 0; i < max_len; i += inc)
    {
        uint16_t uchar = unicode ? extract_16bits(data + i) : data[i];
        if (uchar == 0)
            break;
    }

    char* fname = nullptr;
    const uint32_t real_len = i;

    if (unicode)
    {
        fname = (char*)snort_calloc(real_len + UTF_16_LE_BOM_LEN + 2);
        memcpy(fname, UTF_16_LE_BOM, UTF_16_LE_BOM_LEN);//Prepend with BOM
        memcpy(fname + UTF_16_LE_BOM_LEN, data, real_len);
        *file_name_len = real_len + UTF_16_LE_BOM_LEN;
    }
    else
    {
        fname = (char*)snort_alloc(real_len + 1);
        memcpy(fname, data, real_len);
        fname[real_len] = 0;
        *file_name_len = real_len;
    }
    return fname;
}

void set_smb_reassembled_data(uint8_t* nb_ptr, uint16_t co_len)
{
    snort::Flow* flow = DetectionEngine::get_current_packet()->flow;
    if (flow)
    {
        Dce2SmbFlowData* fd = (Dce2SmbFlowData*)flow->get_flow_data(
            Dce2SmbFlowData::inspector_id);
        if (fd)
        {
            Dce2SmbSessionData* smb_ssn_data = fd->get_smb_session_data();
            smb_ssn_data->set_reassembled_data(nb_ptr, co_len);
        }
    }
}

