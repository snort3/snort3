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
// extractor_dns.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_dns.h"

#include "flow/flow_key.h"
#include "profiler/profiler.h"
#include "pub_sub/dns_events.h"

#include "extractor.h"
#include "extractor_enums.h"

using namespace snort;
using namespace std;

static uint64_t get_trans_id(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_trans_id();
}

static uint64_t get_qclass(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_query_class();
}

static uint64_t get_qtype(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_query_type();
}

static uint64_t get_rcode(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_rcode();
}

static uint64_t get_Z(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_Z();
}

static const map<string, ExtractorEvent::NumGetFn> sub_num_getters =
{
    {"trans_id", get_trans_id},
    {"qclass", get_qclass},
    {"qtype", get_qtype},
    {"rcode", get_rcode},
    {"Z", get_Z}
};

static const map<PktType, string> pkttype_to_protocol =
{
    {PktType::TCP, "TCP"},
    {PktType::UDP, "UDP"}
};

static const char* get_proto(const DataEvent*, const Flow* f)
{
    const auto& iter = pkttype_to_protocol.find(f->pkt_type);
    return (iter != pkttype_to_protocol.end()) ? iter->second.c_str() : "";
}

static const char* get_query(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_query().c_str();
}

static const char* get_qclass_name(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_query_class_name().c_str();
}

static const char* get_qtype_name(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_query_type_name().c_str();
}

static const char* get_rcode_name(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_rcode_name().c_str();
}

static const char* get_AA(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_AA() ? "T" : "F";
}

static const char* get_TC(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_TC() ? "T" : "F";
}

static const char* get_RD(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_RD() ? "T" : "F";
}

static const char* get_RA(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_RA() ? "T" : "F";
}

static const char* get_answers(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_answers().c_str();
}

static const char* get_TTLs(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_TTLs().c_str();
}

static const char* get_rejected(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_rejected() ? "T" : "F";
}

static const char* get_auth(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_auth().c_str();
}

static const char* get_addl(const DataEvent* event, const Flow*)
{
    return ((const DnsResponseEvent*)event)->get_addl().c_str();
}

static const map<string, ExtractorEvent::BufGetFn> sub_buf_getters =
{
    {"proto", get_proto},
    {"query", get_query},
    {"qclass_name", get_qclass_name},
    {"qtype_name", get_qtype_name},
    {"rcode_name", get_rcode_name},
    {"AA", get_AA},
    {"TC", get_TC},
    {"RD", get_RD},
    {"RA", get_RA},
    {"answers", get_answers},
    {"TTLs", get_TTLs},
    {"rejected", get_rejected},
    {"auth", get_auth},
    {"addl", get_addl}
};

THREAD_LOCAL const snort::Connector::ID* DnsResponseExtractor::log_id = nullptr;

DnsResponseExtractor::DnsResponseExtractor(Extractor& i, uint32_t t, const vector<string>& fields)
    : ExtractorEvent(ServiceType::DNS, i, t)
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

    DataBus::subscribe_global(dns_pub_key, DnsEventIds::DNS_RESPONSE,
        new Resp(*this, S_NAME), i.get_snort_config());
}

void DnsResponseExtractor::internal_tinit(const snort::Connector::ID* id)
{
    log_id = id;
}

void DnsResponseExtractor::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);

    if (!filter(flow))
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

TEST_CASE("DNS Proto", "[extractor]")
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

#endif
