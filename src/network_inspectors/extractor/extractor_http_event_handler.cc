//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// extractor_http_event_handler.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_event_handlers.h"

#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "profiler/profiler.h"
#include "pub_sub/http_transaction_end_event.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"
#include "utils/util_net.h"

using namespace snort;
using namespace std;

static const Field& get_method(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_method();
}

static const Field& get_host(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_host_hdr();
}

static const Field& get_user_agent(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_user_agent();
}

static const Field& get_uri(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_uri();
}

static const Field& get_referrer(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_referer_hdr();
}

static const Field& get_origin(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_origin_hdr();
}

static const char* get_version(const DataEvent* event, const Packet*, const Flow*)
{
    HttpEnums::VersionId version = ((const HttpTransactionEndEvent*)event)->get_version();
    const auto& iter = HttpEnums::VersionEnumToStr.find(version);

    return iter != HttpEnums::VersionEnumToStr.end() ? iter->second : "";
}

static const Field& get_stat_code(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_stat_code();
}

static const Field& get_stat_msg(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_stat_msg();
}

static uint64_t get_trans_depth(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_trans_depth();
}

static uint64_t get_request_body_len(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_request_body_len();
}

static uint64_t get_response_body_len(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_response_body_len();
}

static uint64_t get_info_code(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_info_code();
}

static const Field& get_info_msg(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_info_msg();
}

static const char* get_proxied(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_proxied().c_str();
}

static const char* get_orig_filenames(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_filename(HttpCommon::SRC_CLIENT).c_str();
}

static const char* get_resp_filenames(const DataEvent* event, const Packet*, const Flow*)
{
    return ((const HttpTransactionEndEvent*)event)->get_filename(HttpCommon::SRC_SERVER).c_str();
}

static struct timeval get_timestamp(const DataEvent*, const Packet* p, const Flow*)
{
    return p->pkth->ts;
}

static const SfIp& get_ip_src(const DataEvent*, const Packet*, const Flow* flow)
{
    return flow->flags.client_initiated ? flow->client_ip : flow->server_ip;
}

static const SfIp& get_ip_dst(const DataEvent*, const Packet*, const Flow* flow)
{
    return flow->flags.client_initiated ? flow->server_ip : flow->client_ip;
}

static uint64_t get_ip_src_port(const DataEvent*, const Packet*, const Flow* flow)
{
    return flow->client_port;
}

static uint64_t get_ip_dst_port(const DataEvent*, const Packet*, const Flow* flow)
{
    return flow->server_port;
}

static uint64_t get_pkt_num(const DataEvent*, const Packet* p, const Flow*)
{
    return p->context->packet_number;
}

static uint64_t get_uid(const DataEvent*, const Packet*, const Flow* flow)
{
    return ExtractorEvent::get_hash().do_hash((const unsigned char*)flow->key, 0);
}

static const map<string, ExtractorEvent::NtsGetFn> nts_getters =
{
    {"ts", get_timestamp},
};

static const map<string, ExtractorEvent::SipGetFn> sip_getters =
{
    {"id.orig_h", get_ip_src},
    {"id.resp_h", get_ip_dst}
};

static const map<string, ExtractorEvent::StrGetFn> str_getters =
{
    {"version", get_version},
    {"proxied", get_proxied},
    {"orig_filenames", get_orig_filenames},
    {"resp_filenames", get_resp_filenames}
};

static const map<string, ExtractorEvent::NumGetFn> num_getters =
{
    {"id.orig_p", get_ip_src_port},
    {"id.resp_p", get_ip_dst_port},
    {"uid", get_uid},
    {"pkt_num", get_pkt_num},
    {"trans_depth", get_trans_depth},
    {"request_body_len", get_request_body_len},
    {"response_body_len", get_response_body_len},
    {"info_code", get_info_code}
};

static const map<string, HttpExtractorEventHandler::SubGetFn> sub_getters =
{
    {"method", get_method},
    {"host", get_host},
    {"uri", get_uri},
    {"user_agent", get_user_agent},
    {"referrer", get_referrer},
    {"origin", get_origin},
    {"status_code", get_stat_code},
    {"status_msg", get_stat_msg},
    {"info_msg", get_info_msg}
};

template<class T, class U, class V>
static inline bool append(T& cont, const U& map, const V& key)
{
    auto it = map.find(key);

    if (it == map.end())
        return false;

    cont.emplace_back(it->first.c_str(), it->second);

    return true;
}

HttpExtractorEventHandler::HttpExtractorEventHandler(uint32_t t, const vector<string>& fields, ExtractorLogger& l)
    : DataHandler(S_NAME), ExtractorEvent(t, l)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(str_fields, str_getters, f))
            continue;
        if (append(sub_fields, sub_getters, f))
            continue;
    }
}

template<>
void ExtractorEvent::log<vector<HttpExtractorEventHandler::SubField>, DataEvent*, Packet*, Flow*, bool>(
    const vector<HttpExtractorEventHandler::SubField>& fields, DataEvent* event, Packet* pkt, Flow* flow, bool strict)
{
    for (const auto& f : fields)
    {
        const auto& d = f.get(event, pkt, flow);
        if (d.length() > 0)
            logger.add_field(f.name, (const char*)d.start(), d.length());
        else if (strict)
            logger.add_field(f.name, "");
    }
}

void HttpExtractorEventHandler::handle(DataEvent& event, Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(extractor_perf_stats);
    uint32_t tid;

#ifndef DISABLE_TENANT_ID
    tid = flow->key->tenant_id;
#else
    tid = 0;
#endif

    if (tenant_id != tid)
        return;

    Packet* packet = DetectionEngine::get_current_packet();

    logger.open_record();
    log(nts_fields, &event, packet, flow);
    log(sip_fields, &event, packet, flow);
    log(num_fields, &event, packet, flow);
    log(str_fields, &event, packet, flow);
    log(sub_fields, &event, packet, flow, logger.is_strict());
    logger.close_record();

    extractor_stats.total_event++;
}

vector<const char*> HttpExtractorEventHandler::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (const auto& f : sub_fields)
        res.push_back(f.name);

    return res;
}
