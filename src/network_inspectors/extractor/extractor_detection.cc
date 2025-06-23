//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_detection.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_detection.h"

#include "profiler/profiler.h"
#include "pub_sub/detection_events.h"

#include "extractor.h"

using namespace snort;
using namespace std;

namespace builtin
{
static const char* get_msg(const DataEvent* event, const Flow*)
{
    return ((const IpsQueuingEvent*)event)->get_stripped_msg().c_str();
}

static const char* get_proto(const DataEvent*, const Flow*)
{
    const Packet* p = ExtractorEvent::get_packet();

    if (p != nullptr)
        return p->get_type();

    return nullptr;
}

static const char* get_source(const DataEvent*, const Flow* flow)
{
    if (flow->gadget)
        return flow->gadget->get_name();

    return "";
}

static uint64_t get_sid(const DataEvent* event, const Flow*)
{
    return (uint64_t)((const IpsQueuingEvent*)event)->get_sid();
}

static uint64_t get_gid(const DataEvent* event, const Flow*)
{
    return (uint64_t)((const IpsQueuingEvent*)event)->get_gid();
}

static const map<string, ExtractorEvent::BufGetFn> sub_buf_getters =
{
    {"msg", get_msg},
    {"source", get_source},
    {"proto", get_proto},
};

static const map<string, ExtractorEvent::NumGetFn> gid_sid_getters =
{
    {"gid", get_gid},
    {"sid", get_sid},
};
}

THREAD_LOCAL const snort::Connector::ID* BuiltinExtractor::log_id = nullptr;

BuiltinExtractor::BuiltinExtractor(Extractor& i, uint32_t t, const vector<string>& fields)
    : ExtractorEvent(ServiceType::IPS_BUILTIN, i, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(num_fields, builtin::gid_sid_getters, f))
            continue;
        if (append(buf_fields, builtin::sub_buf_getters, f))
            continue;
    }

    DataBus::subscribe_global(de_pub_key, DetectionEventIds::BUILTIN, new IpsBuiltin(*this, S_NAME), i.get_snort_config());
}

void BuiltinExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

void BuiltinExtractor::handle(DataEvent& event, Flow* flow)
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

namespace ips
{
static const char* get_msg(const DataEvent* event, const Flow*)
{
    return ((const IpsRuleEvent*)event)->get_stripped_msg().c_str();
}

static const char* get_action(const DataEvent* event, const Flow*)
{
    return ((const IpsRuleEvent*)event)->get_action();
}

static const vector<const char*>& get_refs(const DataEvent* event, const Flow*)
{
    return ((const IpsRuleEvent*)event)->get_references();
}

static const char* get_proto(const DataEvent*, const Flow*)
{
    const Packet* p = ExtractorEvent::get_packet();

    if (p != nullptr)
        return p->get_type();

    return nullptr;
}

static const char* get_source(const DataEvent*, const Flow* flow)
{
    if (flow->gadget)
        return flow->gadget->get_name();

    return "";
}

static uint64_t get_sid(const DataEvent* event, const Flow*)
{
    return (uint64_t)((const IpsRuleEvent*)event)->get_sid();
}

static uint64_t get_gid(const DataEvent* event, const Flow*)
{
    return (uint64_t)((const IpsRuleEvent*)event)->get_gid();
}

static uint64_t get_rev(const DataEvent* event, const Flow*)
{
    return (uint64_t)((const IpsRuleEvent*)event)->get_rev();
}

static const map<string, ExtractorEvent::BufGetFn> sub_buf_getters =
{
    {"msg", get_msg},
    {"action", get_action},
    {"source", get_source},
    {"proto", get_proto},
};

static const map<string, ExtractorEvent::NumGetFn> gid_sid_rev_getters =
{
    {"gid", get_gid},
    {"sid", get_sid},
    {"rev", get_rev},
};

static const map<string, IpsUserExtractor::VecGetFn> vec_getters =
{
    {"refs", get_refs}
};
}

THREAD_LOCAL const snort::Connector::ID* IpsUserExtractor::log_id = nullptr;

IpsUserExtractor::IpsUserExtractor(Extractor& i, uint32_t t, const vector<string>& fields, bool contextual)
    : ExtractorEvent(ServiceType::IPS_USER, i, t)
{
    for (const auto& f : fields)
    {
        if (append(nts_fields, nts_getters, f))
            continue;
        if (append(sip_fields, sip_getters, f))
            continue;
        if (append(num_fields, num_getters, f))
            continue;
        if (append(num_fields, ips::gid_sid_rev_getters, f))
            continue;
        if (append(buf_fields, ips::sub_buf_getters, f))
            continue;
        if (append(vec_fields, ips::vec_getters, f))
            continue;
    }

    auto event = contextual ? DetectionEventIds::CONTEXT_LOGGING : DetectionEventIds::IPS_LOGGING;
    DataBus::subscribe_global(de_pub_key, event, new IpsUser(*this, S_NAME), i.get_snort_config());
}

void IpsUserExtractor::internal_tinit(const snort::Connector::ID* service_id)
{ log_id = service_id; }

void IpsUserExtractor::handle(DataEvent& event, Flow* flow)
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
    log(vec_fields, &event, flow);
    logger->close_record(*log_id);
}

vector<const char*> IpsUserExtractor::get_field_names() const
{
    vector<const char*> res = ExtractorEvent::get_field_names();

    for (const auto& f : vec_fields)
        res.push_back(f.name);

    return res;
}

