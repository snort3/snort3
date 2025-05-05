//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_conn.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_conn.h"

#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "profiler/profiler.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"
#include "stream/tcp/tcp_session.h"
#include "stream/udp/udp_session.h"
#include "utils/util.h"
#include "utils/util_net.h"

#include "extractor.h"
#include "extractor_enums.h"

using namespace snort;
using namespace std;

static uint64_t get_orig_pkts(const DataEvent*, const Flow* f)
{
    return f->flowstats.client_pkts;
}

static uint64_t get_resp_pkts(const DataEvent*, const Flow* f)
{
    return f->flowstats.server_pkts;
}

static uint64_t get_duration(const DataEvent*, const Flow* f)
{
    return f->last_data_seen - f->flowstats.start_time.tv_sec;
}

static uint64_t get_orig_bytes_tcp(const TcpSession* tcpssn)
{
    uint32_t client_bytes = tcpssn->client.get_snd_nxt() - tcpssn->client.get_iss();
    // get_snd_nxt is the next expected sequence number (last seen + 1)
    if (client_bytes != 0)
        client_bytes -= 1;
    return client_bytes; 
}

static uint64_t get_orig_bytes(const DataEvent*, const Flow* f)
{
    if (f->session == nullptr)
        return 0;
    if (f->pkt_type == PktType::TCP)
        return get_orig_bytes_tcp((const TcpSession*)f->session);
    else if (f->pkt_type == PktType::UDP)
        return ((UdpSession*)(f->session))->payload_bytes_seen_client;

    return 0;
}

static uint64_t get_resp_bytes_tcp(const TcpSession* tcpssn)
{
    uint32_t server_bytes = tcpssn->server.get_snd_nxt() - tcpssn->server.get_iss();
    if (server_bytes != 0)
        server_bytes -= 1;
    return server_bytes;
}

static uint64_t get_resp_bytes(const DataEvent*, const Flow* f)
{
    if (f->session == nullptr)
        return 0;
    
    if (f->pkt_type == PktType::TCP)
        return get_resp_bytes_tcp((const TcpSession*)f->session);
    else if (f->pkt_type == PktType::UDP)
        return ((UdpSession*)(f->session))->payload_bytes_seen_server;

    return 0;
}

static const map<string, ExtractorEvent::NumGetFn> sub_num_getters =
{
    {"orig_pkts", get_orig_pkts},
    {"resp_pkts", get_resp_pkts},
    {"duration", get_duration},
    {"orig_bytes", get_orig_bytes},
    {"resp_bytes", get_resp_bytes}
};

static const char* get_service(const DataEvent*, const Flow* f)
{
    SnortConfig* sc = SnortConfig::get_main_conf();
    return sc->proto_ref->get_name(f->ssn_state.snort_protocol_id);
}

static const map<PktType, string> pkttype_to_protocol =
{
    {PktType::TCP, "TCP"},
    {PktType::UDP, "UDP"},
    {PktType::IP, "IP"},
    {PktType::ICMP, "ICMP"}
};

static const char* get_proto(const DataEvent*, const Flow* f)
{
    const auto& iter = pkttype_to_protocol.find(f->pkt_type);
    return (iter != pkttype_to_protocol.end()) ? iter->second.c_str() : "";
}

static const map<string, ExtractorEvent::BufGetFn> sub_buf_getters =
{
    {"proto", get_proto},
    {"service", get_service}
};

THREAD_LOCAL const snort::Connector::ID* ConnExtractor::log_id = nullptr;

ConnExtractor::ConnExtractor(Extractor& i, uint32_t t, const vector<string>& fields)
    : ExtractorEvent(ServiceType::CONN, i, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(num_fields, sub_num_getters, f))
            continue;
        if (append(buf_fields, sub_buf_getters, f))
            continue;
    }

    DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::FLOW_END,
        new Eof(*this, S_NAME), i.get_snort_config());
}

void ConnExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

void ConnExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    if (flow->pkt_type < PktType::IP or flow->pkt_type > PktType::ICMP or !filter(flow))
        return;

    extractor_stats.total_events++;

    logger->open_record();
    log(nts_fields, &event, flow);
    log(sip_fields, &event, flow);
    log(num_fields, &event, flow);
    log(buf_fields, &event, flow);
    logger->close_record(*log_id);
}

//-------------------------------------------------------------------------
//  Unit Tests
//-------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include <memory.h>

TEST_CASE("Conn Proto", "[extractor]")
{
    Flow* flow = new Flow;
    InspectionPolicy ins;
    set_inspection_policy(&ins);
    NetworkPolicy net;
    set_network_policy(&net);

    SECTION("unknown")
    {
        flow->pkt_type = PktType::NONE;
        const char* proto = get_proto(nullptr, flow);
        CHECK_FALSE(strcmp("", proto));
    }

    delete flow;
}

TEST_CASE("Conn payload bytes", "[extractor]")
{
    Flow* flow = new Flow;
    InspectionPolicy ins;
    set_inspection_policy(&ins);
    NetworkPolicy net;
    set_network_policy(&net);

    SECTION("no session")
    {
        uint64_t bytes = get_orig_bytes(nullptr, flow);
        CHECK(bytes == 0);
        bytes = get_resp_bytes(nullptr, flow);
        CHECK(bytes == 0);
    }

    delete flow;
}

#endif
