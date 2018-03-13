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

//dce_tcp.h author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifndef DCE_UDP_H
#define DCE_UDP_H

#include "profiler/profiler_defs.h"

#include "dce_common.h"

#define DCE2_UDP_NAME "dce_udp"
#define DCE2_UDP_HELP "dce over udp inspection"

#define DCE2_MOCK_HDR_LEN__CL  (sizeof(DceRpcClHdr))

struct dce2UdpStats
{
    /* The common stats block has to be at the beginning followed
       by the protocol specific stats */

    /*common stats -defined in common.h*/
    PegCount events;

    /*DCE UDP specific*/
    PegCount udp_sessions;
    PegCount udp_pkts;
    PegCount cl_request;
    PegCount cl_ack;
    PegCount cl_cancel;
    PegCount cl_cli_fack;
    PegCount cl_ping;
    PegCount cl_response;
    PegCount cl_reject;
    PegCount cl_cancel_ack;
    PegCount cl_srv_fack;
    PegCount cl_fault;
    PegCount cl_nocall;
    PegCount cl_working;
    PegCount cl_other_req;
    PegCount cl_other_resp;
    PegCount cl_fragments;
    PegCount cl_max_frag_size;
    PegCount cl_frag_reassembled;
    PegCount cl_max_seqnum;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

extern THREAD_LOCAL dce2UdpStats dce2_udp_stats;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_main;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_session;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_new_session;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_detect;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_log;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_cl_acts;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_cl_frag;
extern THREAD_LOCAL snort::ProfileStats dce2_udp_pstat_cl_reass;

struct DceRpcClHdr   /* Connectionless header */
{
    uint8_t rpc_vers;
    uint8_t ptype;
    uint8_t flags1;
    uint8_t flags2;
    uint8_t drep[3];
    uint8_t serial_hi;
    Uuid object;
    Uuid if_id;
    Uuid act_id;
    uint32_t server_boot;
    uint32_t if_vers;
    uint32_t seqnum;
    uint16_t opnum;
    uint16_t ihint;
    uint16_t ahint;
    uint16_t len;
    uint16_t fragnum;
    uint8_t auth_proto;
    uint8_t serial_lo;
};

enum DceRpcClFlags1
{
    DCERPC_CL_FLAGS1__RESERVED_01 = 0x01,
    DCERPC_CL_FLAGS1__LASTFRAG = 0x02,
    DCERPC_CL_FLAGS1__FRAG = 0x04,
    DCERPC_CL_FLAGS1__NOFACK = 0x08,
    DCERPC_CL_FLAGS1__MAYBE = 0x10,
    DCERPC_CL_FLAGS1__IDEMPOTENT = 0x20,
    DCERPC_CL_FLAGS1__BROADCAST = 0x40,
    DCERPC_CL_FLAGS1__RESERVED_80 = 0x80
};

inline uint8_t DceRpcClRpcVers(const DceRpcClHdr* cl)
{
    return cl->rpc_vers;
}

inline uint8_t DceRpcClPduType(const DceRpcClHdr* cl)
{
    return cl->ptype;
}

inline DceRpcBoFlag DceRpcClByteOrder(const DceRpcClHdr* cl)
{
    return DceRpcByteOrder(cl->drep[0]);
}

inline uint16_t DceRpcClLen(const DceRpcClHdr* cl)
{
    return DceRpcNtohs(&cl->len, DceRpcClByteOrder(cl));
}

inline uint16_t DceRpcClOpnum(const DceRpcClHdr* cl)
{
    return DceRpcNtohs(&cl->opnum, DceRpcClByteOrder(cl));
}

inline uint32_t DceRpcClSeqNum(const DceRpcClHdr* cl)
{
    return DceRpcNtohl(&cl->seqnum, DceRpcClByteOrder(cl));
}

inline const Uuid* DceRpcClIface(const DceRpcClHdr* cl)
{
    return &cl->if_id;
}

inline uint32_t DceRpcClIfaceVers(const DceRpcClHdr* cl)
{
    return DceRpcNtohl(&cl->if_vers, DceRpcClByteOrder(cl));
}

inline uint16_t DceRpcClFragNum(const DceRpcClHdr* cl)
{
    return DceRpcNtohs(&cl->fragnum, DceRpcClByteOrder(cl));
}

inline int DceRpcClFragFlag(const DceRpcClHdr* cl)
{
    return cl->flags1 & DCERPC_CL_FLAGS1__FRAG;
}

inline bool DceRpcClFirstFrag(const DceRpcClHdr* cl)
{
    return (DceRpcClFragFlag(cl) && (DceRpcClFragNum(cl) == 0));
}

inline int DceRpcClLastFrag(const DceRpcClHdr* cl)
{
    return cl->flags1 & DCERPC_CL_FLAGS1__LASTFRAG;
}

inline bool DceRpcClFrag(const DceRpcClHdr* cl)
{
    if (DceRpcClFragFlag(cl))
    {
        if (DceRpcClLastFrag(cl) && (DceRpcClFragNum(cl) == 0))
            return false;

        return true;
    }

    return false;
}

struct DCE2_ClTracker
{
    DCE2_List* act_trackers;  /* List of activity trackers */
};

struct DCE2_UdpSsnData
{
    DCE2_SsnData sd;  // This member must be first
    DCE2_ClTracker cl_tracker;
};

class Dce2UdpFlowData : public snort::FlowData
{
public:
    Dce2UdpFlowData();
    ~Dce2UdpFlowData() override;

    static void init()
    {
        inspector_id = snort::FlowData::create_flow_data_id();
    }

    static unsigned inspector_id;
    DCE2_UdpSsnData dce2_udp_session;
};

DCE2_UdpSsnData* get_dce2_udp_session_data(snort::Flow*);

void DCE2_ClProcess(DCE2_SsnData* sd, DCE2_ClTracker* clt);
void DCE2_ClInitRdata(uint8_t*);

#endif

