//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractors.h author Maya Dagon <mdagon@cisco.com>

#ifndef EXTRACTORS_H
#define EXTRACTORS_H

#include <sys/time.h>
#include <vector>

#include "detection/detection_engine.h"
#include "flow/flow_key.h"
#include "framework/data_bus.h"
#include "framework/connector.h"
#include "sfip/sf_ip.h"
#include "time/packet_time.h"

#include "extractor.h"
#include "extractor_enums.h"
#include "extractor_logger.h"

template <typename Ret, class... Context>
struct DataField
{
    DataField(const char* name, Ret (*get)(Context...)) : name(name), get(get) { }

    const char* name;
    Ret (*get)(Context...);
};

class ExtractorEvent
{
public:
    using DataEvent = snort::DataEvent;
    using DataHandler = snort::DataHandler;
    using Flow = snort::Flow;
    using Packet = snort::Packet;
    using SfIp = snort::SfIp;

    using BufGetFn = const char* (*) (const DataEvent*, const Flow*);
    using BufField = DataField<const char*, const DataEvent*, const Flow*>;
    using SipGetFn = const SfIp& (*) (const DataEvent*, const Flow*);
    using SipField = DataField<const SfIp&, const DataEvent*, const Flow*>;
    using NumGetFn = uint64_t (*) (const DataEvent*, const Flow*);
    using NumField = DataField<uint64_t, const DataEvent*, const Flow*>;
    using NtsGetFn = struct timeval (*) (const DataEvent*, const Flow*);
    using NtsField = DataField<struct timeval, const DataEvent*, const Flow*>;
    using StrGetFn = std::pair<const char*, uint16_t> (*) (const DataEvent*, const Flow*);
    using StrField = DataField<std::pair<const char*, uint16_t>, const DataEvent*, const Flow*>;

    static snort::FlowHashKeyOps& get_hash()
    {
        static thread_local snort::FlowHashKeyOps flow_key_ops(0);
        return flow_key_ops;
    }

    static const snort::Packet* get_packet()
    { return snort::DetectionEngine::get_context() ? snort::DetectionEngine::get_current_packet() : nullptr; }

    virtual ~ExtractorEvent() {}

    void tinit(ExtractorLogger*, const snort::Connector::ID*);

    Extractor& get_inspector() const { return inspector; }

    virtual std::vector<const char*> get_field_names() const;

    void handle(DataEvent&, Flow*) {}

protected:
    template<typename T>
    struct Handler : public DataHandler
    {
        Handler(T& owner, const char* name) : DataHandler(name), owner(owner) {}
        void handle(DataEvent& e, Flow* f) override { owner.handle(e, f); }
        T& owner;
    };

    static struct timeval get_timestamp(const DataEvent*, const Flow*)
    {
        const Packet* p = ExtractorEvent::get_packet();

        if (p != nullptr)
            return p->pkth->ts;

        struct timeval timestamp;
        snort::packet_gettimeofday(&timestamp);
        return timestamp;
    }

    static const SfIp& get_ip_src(const DataEvent*, const Flow* flow)
    { return  flow->client_ip; }

    static const SfIp& get_ip_dst(const DataEvent*, const Flow* flow)
    { return flow->server_ip; }

    static uint64_t get_ip_src_port(const DataEvent*, const Flow* flow)
    { return flow->client_port; }

    static uint64_t get_ip_dst_port(const DataEvent*, const Flow* flow)
    { return flow->server_port; }

    static uint64_t get_tenant_id(const DataEvent*, const Flow* flow)
    {
#ifdef DISABLE_TENANT_ID
        return 0;
#else
        return flow->key->tenant_id;
#endif
    }

    static uint64_t get_pkt_num(const DataEvent*, const Flow*)
    {
        const Packet* p = ExtractorEvent::get_packet();

        if (p != nullptr)
            return p->context->packet_number;

        return 0;
    }

    static uint64_t get_uid(const DataEvent*, const Flow* flow)
    { return ExtractorEvent::get_hash().do_hash((const unsigned char*)flow->key, 0); }

    template<typename T, class... Context>
    void log(const T& fields, Context... context)
    {
        for (const auto& f : fields)
            logger->add_field(f.name, f.get(context...));
    }

    void log(const std::vector<StrField>& fields, DataEvent* event, Flow* flow, bool strict)
    {
        for (const auto& f : fields)
        {
            const auto& str = f.get(event, flow);
            if (str.second > 0)
                logger->add_field(f.name, (const char*)str.first, str.second);
            else if (strict)
                logger->add_field(f.name, "");
        }
    }

    template<class T, class U, class V>
    bool append(T& cont, const U& map, const V& key)
    {
        auto it = map.find(key);
        if (it != map.end())
            cont.emplace_back(it->first.c_str(), it->second);
        return it != map.end();
    }

    inline bool filter(Flow*);

    ExtractorEvent(ServiceType st, Extractor& i, uint32_t tid)
        : service_type(st), pick_by_default(i.get_default_filter()), tenant_id(tid), inspector(i) { }

    virtual void internal_tinit(const snort::Connector::ID*) = 0;

    static THREAD_LOCAL ExtractorLogger* logger;

    ServiceType service_type;
    bool pick_by_default;
    uint32_t tenant_id;
    Extractor& inspector;

    std::vector<NtsField> nts_fields;
    std::vector<SipField> sip_fields;
    std::vector<NumField> num_fields;
    std::vector<BufField> buf_fields;
    std::vector<StrField> str_fields;

    static const std::map<std::string, ExtractorEvent::NtsGetFn> nts_getters;
    static const std::map<std::string, ExtractorEvent::SipGetFn> sip_getters;
    static const std::map<std::string, ExtractorEvent::NumGetFn> num_getters;
};

bool ExtractorEvent::filter(Flow* flow)
{
    if (!flow)
        return false;

    auto& filter = flow->data_log_filtering_state;
    assert(filter.size() >= ServiceType::MAX);

#ifdef DISABLE_TENANT_ID
    uint32_t tid = 0;
#else
    uint32_t tid = flow->key->tenant_id;
#endif

    // computed by external filter
    if (filter.test(ServiceType::ANY))
        return filter.test(service_type) and tenant_id == tid;

    if (!pick_by_default)
        return false;

    // extractor sets targeted filtering
    filter.set(service_type);

    return filter.test(service_type) and tenant_id == tid;
}

#endif
