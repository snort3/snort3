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
#include "utils/util.h"
#include "utils/util_net.h"

#include "extractor.h"
#include "extractor_enums.h"

using namespace snort;
using namespace std;

static uint64_t get_orig_pkts(const DataEvent*, const Packet*, const Flow* f)
{
    return f->flowstats.client_pkts;
}

static uint64_t get_resp_pkts(const DataEvent*, const Packet*, const Flow* f)
{
    return f->flowstats.server_pkts;
}

static uint64_t get_duration(const DataEvent*, const Packet*, const Flow* f)
{
    return f->last_data_seen - f->flowstats.start_time.tv_sec;
}

static const map<string, ExtractorEvent::NumGetFn> sub_num_getters =
{
    {"orig_pkts", get_orig_pkts},
    {"resp_pkts", get_resp_pkts},
    {"duration", get_duration}
};

static const char* get_service(const DataEvent*, const Packet*, const Flow* f)
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

static const char* get_proto(const DataEvent*, const Packet*, const Flow* f)
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
    : ExtractorEvent(i, t)
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

    DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FLOW_END, new Eof(*this, S_NAME));
}

void ConnExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

void ConnExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    uint32_t tid = 0;

    if ((flow->pkt_type < PktType::IP) or (flow->pkt_type > PktType::ICMP))
        return;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#endif

    if (tenant_id != tid)
        return;

    Packet* packet = (DetectionEngine::get_context()) ? DetectionEngine::get_current_packet() : nullptr;

    extractor_stats.total_event++;

    logger->open_record();
    log(nts_fields, &event, packet, flow);
    log(sip_fields, &event, packet, flow);
    log(num_fields, &event, packet, flow);
    log(buf_fields, &event, packet, flow);
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
        const char* proto = get_proto(nullptr, nullptr, flow);
        CHECK_FALSE(strcmp("", proto));
    }

    delete flow;
}

#endif
