//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

//dce_expected_session.cc author Eduard Burmai <eburmai@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_expected_session.h"

#include "framework/pig_pen.h"
#include "pub_sub/dcerpc_events.h"
#include "stream/stream.h"

#include "dce_tcp.h"

using namespace snort;

void DceExpSsnManager::create_expected_session(const SfIp* ept_ip,
    uint16_t ept_port, const char* mod_name)
{
    Packet* pkt = DetectionEngine::get_current_packet();
    Dce2Tcp* inspector = (Dce2Tcp*)PigPen::get_inspector(mod_name, true);
    DceExpSsnManager& esm = inspector->get_esm();

    const SfIp* src_ip = pkt->ptrs.ip_api.get_dst();
    PktType type = esm.get_pkt_type();
    IpProtocol proto = esm.get_ip_proto();
    SnortProtocolId protocol_id = esm.get_proto_id();

    if (esm.create_expected_session_impl(pkt, src_ip, 0,
        ept_ip, ept_port, type, proto, protocol_id))
        return;

    dce2_tcp_stats.tcp_expected_sessions++;

    DceExpectedSessionEvent map_resp_event(pkt, src_ip, 0,
        ept_ip, ept_port, proto, protocol_id);
    DataBus::publish(Dce2Tcp::pub_id, DceTcpEventIds::EXP_SESSION, map_resp_event, pkt->flow);
}

DceTcpExpSsnManager::DceTcpExpSsnManager(const dce2TcpProtoConf& config) :
    DceExpSsnManager(IpProtocol::TCP, PktType::TCP), pc(config) { }

int DceTcpExpSsnManager::create_expected_session_impl(Packet* pkt,
    const snort::SfIp* src_ip, uint16_t src_port,
    const snort::SfIp* dst_ip, uint16_t dst_port,
    PktType type, IpProtocol proto, SnortProtocolId protocol_id)
{
    Dce2TcpFlowData* fd = new Dce2TcpFlowData;

    fd->state = DCE2_TCP_FLOW__EXPECTED;
    memset(&fd->dce2_tcp_session, 0, sizeof(DCE2_TcpSsnData));
    DCE2_CoInitTracker(&fd->dce2_tcp_session.co_tracker);
    DCE2_ResetRopts(&fd->dce2_tcp_session.sd, pkt);

    fd->dce2_tcp_session.sd.trans = DCE2_TRANS_TYPE__TCP;
    fd->dce2_tcp_session.sd.server_policy = pc.common.policy;
    fd->dce2_tcp_session.sd.client_policy = DCE2_POLICY__WINXP;
    fd->dce2_tcp_session.sd.config = (void*)&pc;

    if (Stream::set_snort_protocol_id_expected(pkt, type,
        proto, src_ip, src_port, dst_ip, dst_port, protocol_id, fd, false, false, false, true))
    {
        delete fd;
        return -1;
    }

    return 0;
}

