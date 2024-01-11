//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

//dce_tcp.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#ifndef DCE_TCP_H
#define DCE_TCP_H

#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "profiler/profiler_defs.h"

#include "dce_co.h"
#include "dce_expected_session.h"
#include "dce_tcp_module.h"
#include "dce_tcp_paf.h"

#define DCE2_TCP_NAME "dce_tcp"
#define DCE2_TCP_HELP "dce over tcp inspection"

struct dce2TcpStats
{
    /* common stats - defined in dce_common.h*/
    PegCount events;

    PegCount co_pdus;
    PegCount co_bind;
    PegCount co_bind_ack;
    PegCount co_alter_ctx;
    PegCount co_alter_ctx_resp;
    PegCount co_bind_nack;
    PegCount co_request;
    PegCount co_response;
    PegCount co_cancel;
    PegCount co_orphaned;
    PegCount co_fault;
    PegCount co_auth3;
    PegCount co_shutdown;
    PegCount co_reject;
    PegCount co_ms_pdu;
    PegCount co_other_req;
    PegCount co_other_resp;
    PegCount co_req_fragments;
    PegCount co_resp_fragments;
    PegCount co_cli_max_frag_size;
    PegCount co_cli_min_frag_size;
    PegCount co_cli_seg_reassembled;
    PegCount co_cli_frag_reassembled;
    PegCount co_srv_max_frag_size;
    PegCount co_srv_min_frag_size;
    PegCount co_srv_seg_reassembled;
    PegCount co_srv_frag_reassembled;

    /*DCE TCP specific*/
    PegCount tcp_sessions;
    PegCount tcp_expected_sessions;
    PegCount tcp_expected_realized_sessions;
    PegCount tcp_pkts;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern THREAD_LOCAL dce2TcpStats dce2_tcp_stats;
extern THREAD_LOCAL snort::ProfileStats dce2_tcp_pstat_main;

inline bool DCE2_TcpAutodetect(snort::Packet* p)
{
    if (p->dsize >= sizeof(DceRpcCoHdr))
    {
        const DceRpcCoHdr* co_hdr = (const DceRpcCoHdr*)p->data;

        if ((DceRpcCoVersMaj(co_hdr) == DCERPC_PROTO_MAJOR_VERS__5)
            && (DceRpcCoVersMin(co_hdr) == DCERPC_PROTO_MINOR_VERS__0)
            && ((p->is_from_client()
            && DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND)
            || (p->is_from_server()
            && DceRpcCoPduType(co_hdr) == DCERPC_PDU_TYPE__BIND_ACK))
            && (DceRpcCoFragLen(co_hdr) >= sizeof(DceRpcCoHdr)))
        {
            return true;
        }
    }
    else if ((*p->data == DCERPC_PROTO_MAJOR_VERS__5) && p->is_from_client())
    {
        return true;
    }

    return false;
}

struct DCE2_TcpSsnData
{
    DCE2_SsnData sd;  // This member must be first
    DCE2_CoTracker co_tracker;
};

enum DCE2_TcpFlowState
{
    DCE2_TCP_FLOW__COMMON,
    DCE2_TCP_FLOW__EXPECTED,
    DCE2_TCP_FLOW__REALIZED
};

class Dce2TcpFlowData : public snort::FlowData
{
public:
    Dce2TcpFlowData();
    ~Dce2TcpFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    DCE2_TcpSsnData dce2_tcp_session = {};
    DCE2_TcpFlowState state = DCE2_TCP_FLOW__COMMON;
};

class Dce2Tcp : public snort::Inspector
{
public:
    explicit Dce2Tcp(const dce2TcpProtoConf&);

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override;
    void clear(snort::Packet*) override;

    DceTcpExpSsnManager& get_esm()
    { return esm; }

    bool is_control_channel() const override
    { return true; }

    snort::StreamSplitter* get_splitter(bool c2s) override
    { return new Dce2TcpSplitter(c2s); }

    static unsigned pub_id;

private:
    dce2TcpProtoConf config;
    DceTcpExpSsnManager esm;
};

DCE2_TcpSsnData* get_dce2_tcp_session_data(snort::Flow*);

#endif

