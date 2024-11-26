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

#include "extractor_logger.h"

class Extractor;

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

    using BufGetFn = const char* (*) (const DataEvent*, const Packet*, const Flow*);
    using BufField = DataField<const char*, const DataEvent*, const Packet*, const Flow*>;
    using SipGetFn = const SfIp& (*) (const DataEvent*, const Packet*, const Flow*);
    using SipField = DataField<const SfIp&, const DataEvent*, const Packet*, const Flow*>;
    using NumGetFn = uint64_t (*) (const DataEvent*, const Packet*, const Flow*);
    using NumField = DataField<uint64_t, const DataEvent*, const Packet*, const Flow*>;
    using NtsGetFn = struct timeval (*) (const DataEvent*, const Packet*, const Flow*);
    using NtsField = DataField<struct timeval, const DataEvent*, const Packet*, const Flow*>;
    using StrGetFn = std::pair<const char*, uint16_t> (*) (const DataEvent*, const Packet*, const Flow*);
    using StrField = DataField<std::pair<const char*, uint16_t>, const DataEvent*, const Packet*, const Flow*>;

    static snort::FlowHashKeyOps& get_hash()
    {
        static thread_local snort::FlowHashKeyOps flow_key_ops(0);
        return flow_key_ops;
    }

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

    static struct timeval get_timestamp(const DataEvent*, const Packet* p, const Flow*)
    { return p->pkth->ts; }

    static const SfIp& get_ip_src(const DataEvent*, const Packet*, const Flow* flow)
    { return flow->flags.client_initiated ? flow->client_ip : flow->server_ip; }

    static const SfIp& get_ip_dst(const DataEvent*, const Packet*, const Flow* flow)
    { return flow->flags.client_initiated ? flow->server_ip : flow->client_ip; }

    static uint64_t get_ip_src_port(const DataEvent*, const Packet*, const Flow* flow)
    { return flow->client_port; }

    static uint64_t get_ip_dst_port(const DataEvent*, const Packet*, const Flow* flow)
    { return flow->server_port; }

    static uint64_t get_pkt_num(const DataEvent*, const Packet* p, const Flow*)
    { return p->context->packet_number; }

    static uint64_t get_uid(const DataEvent*, const Packet*, const Flow* flow)
    { return ExtractorEvent::get_hash().do_hash((const unsigned char*)flow->key, 0); }

    template<typename T, class... Context>
    void log(const T& fields, Context... context)
    {
        for (const auto& f : fields)
            logger->add_field(f.name, f.get(context...));
    }

    void log(const std::vector<StrField>& fields, DataEvent* event, Packet* pkt, Flow* flow, bool strict)
    {
        for (const auto& f : fields)
        {
            const auto& str = f.get(event, pkt, flow);
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

    ExtractorEvent(Extractor& i, uint32_t tid) : tenant_id(tid), inspector(i)
    { }

    virtual void internal_tinit(const snort::Connector::ID*) = 0;

    uint32_t tenant_id;
    Extractor& inspector;
    static THREAD_LOCAL ExtractorLogger* logger;

    std::vector<NtsField> nts_fields;
    std::vector<SipField> sip_fields;
    std::vector<NumField> num_fields;
    std::vector<BufField> buf_fields;
    std::vector<StrField> str_fields;

    static const std::map<std::string, ExtractorEvent::NtsGetFn> nts_getters;
    static const std::map<std::string, ExtractorEvent::SipGetFn> sip_getters;
    static const std::map<std::string, ExtractorEvent::NumGetFn> num_getters;
};

#endif
