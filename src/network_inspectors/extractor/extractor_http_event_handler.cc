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
#include "framework/value.h"
#include "profiler/profiler.h"
#include "pub_sub/http_transaction_end_event.h"
#include "service_inspectors/http_inspect/http_transaction.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"
#include "utils/util_net.h"

using namespace snort;


typedef Value* (*GetFunc) (DataEvent*, Packet*, Flow*);

// HttpTransactionEnd specific
Value* get_method(DataEvent*, Packet*, Flow*);
Value* get_host(DataEvent*, Packet*, Flow*);
Value* get_user_agent(DataEvent*, Packet*, Flow*);
Value* get_uri(DataEvent*, Packet*, Flow*);
Value* get_referrer(DataEvent*, Packet*, Flow*);
Value* get_origin(DataEvent*, Packet*, Flow*);
Value* get_version(DataEvent*, Packet*, Flow*);
Value* get_stat_code(DataEvent*, Packet*, Flow*);
Value* get_stat_msg(DataEvent*, Packet*, Flow*);
Value* get_trans_depth(DataEvent*, Packet*, Flow*);

// Common
Value* get_timestamp(DataEvent*, Packet*, Flow*);
Value* get_ip_src(DataEvent*, Packet*, Flow*);
Value* get_ip_dst(DataEvent*, Packet*, Flow*);
Value* get_ip_src_port(DataEvent*, Packet*, Flow*);
Value* get_ip_dst_port(DataEvent*, Packet*, Flow*);
Value* get_pkt_num(DataEvent*, Packet*, Flow*);
Value* get_uid(DataEvent*, Packet*, Flow*);

static void field_to_string(const Field& field, std::string& value)
{
    if (field.length() > 0)
        value.assign((const char*)field.start(), field.length());
}

Value* get_method(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_method();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_host(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_host_hdr();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_user_agent(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_user_agent();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_uri(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_uri();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_referrer(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_referer_hdr();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_origin(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_origin_hdr();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_version(DataEvent* event, Packet*, Flow*)
{
    HttpEnums::VersionId version = ((HttpTransactionEndEvent*)event)->get_version();
    const auto& iter = HttpEnums::VersionEnumToStr.find(version);
    if (iter != HttpEnums::VersionEnumToStr.end())
        return new Value(iter->second);

    return new Value("");
}

Value* get_stat_code(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_stat_code();
    std::string str;
    field_to_string(field, str);

    return new Value((uint64_t)atoi(str.c_str()));
}

Value* get_stat_msg(DataEvent* event, Packet*, Flow*)
{
    const Field& field = ((HttpTransactionEndEvent*)event)->get_stat_msg();
    std::string str;
    field_to_string(field, str);
    return new Value(str.c_str());
}

Value* get_trans_depth(DataEvent* event, Packet*, Flow*)
{
    const uint64_t trans_depth = ((HttpTransactionEndEvent*)event)->get_trans_depth();
    return new Value(trans_depth);
}

Value* get_timestamp(DataEvent*, Packet* p, Flow*)
{
    char u_sec[8];
    SnortSnprintf(u_sec, sizeof(u_sec),".%06d",(unsigned)p->pkth->ts.tv_usec);
    auto str = std::to_string(p->pkth->ts.tv_sec) + u_sec;

    return new Value(str.c_str());
}

Value* get_ip_src(DataEvent*, Packet*, Flow* flow)
{
    InetBuf src;
    const SfIp& flow_srcip = flow->flags.client_initiated ? flow->client_ip : flow->server_ip;
    sfip_ntop(&flow_srcip, src, sizeof(src));
    std::string str = src;
    return new Value(str.c_str());
}

Value* get_ip_dst(DataEvent*, Packet*, Flow* flow)
{
    InetBuf dst;
    const SfIp& flow_dstip = flow->flags.client_initiated ? flow->server_ip : flow->client_ip;
    sfip_ntop(&flow_dstip, dst, sizeof(dst));
    std::string str = dst;
    return new Value(str.c_str());
}

Value* get_ip_src_port(DataEvent*, Packet*, Flow* flow)
{
    return new Value((uint64_t)flow->client_port);
}

Value* get_ip_dst_port(DataEvent*, Packet*, Flow* flow)
{
    return new Value((uint64_t)flow->server_port);
}

Value* get_pkt_num(DataEvent*, Packet* p, Flow*)
{
    return new Value(p->context->packet_number);
}

Value* get_uid(DataEvent*, Packet*, Flow* f)
{
    unsigned key = ExtractorEvent::get_hash().do_hash((const unsigned char*)f->key, 0);

    return new Value((uint64_t)key);
}

static std::map<std::string, GetFunc> event_getters =
{
    {"ts", get_timestamp},
    {"uid", get_uid},
    {"id.orig_h", get_ip_src},
    {"id.resp_h", get_ip_dst},
    {"id.orig_p", get_ip_src_port},
    {"id.resp_p", get_ip_dst_port},
    {"pkt_num", get_pkt_num},
    {"method", get_method},
    {"host", get_host},
    {"uri", get_uri},
    {"user_agent", get_user_agent},
    {"referrer", get_referrer},
    {"origin", get_origin},
    {"version", get_version},
    {"status_code", get_stat_code},
    {"status_msg", get_stat_msg},
    {"trans_depth", get_trans_depth}
};

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

    Packet* p = DetectionEngine::get_current_packet();

    logger.open_record();
    for (const auto& field : fields)
    {
        auto val = std::unique_ptr<Value>(event_getters[field](&event, p, flow));
        logger.add_field(*val.get());
    }
    logger.close_record();

    extractor_stats.total_event++;
}
