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
// extractor_event_handlers.h author Maya Dagon <mdagon@cisco.com>

#ifndef EXTRACTOR_EVENT_HANDLERS_H
#define EXTRACTOR_EVENT_HANDLERS_H

#include <sys/time.h>
#include <vector>

#include "flow/flow_key.h"
#include "framework/data_bus.h"
#include "sfip/sf_ip.h"

#include "extractor.h"
#include "extractor_logger.h"

template <typename Ret, class... Context>
struct DataField
{
    DataField(const char* name, Ret (*get)(Context...)) : name(name), get(get) { }

    const char* name;
    Ret (*get)(Context...);
};

class Field;

namespace snort
{

class ExtractorEvent
{
public:
    using StrGetFn = const char* (*) (const DataEvent*, const Packet*, const Flow*);
    using StrField = DataField<const char*, const DataEvent*, const Packet*, const Flow*>;
    using SipGetFn = const SfIp& (*) (const DataEvent*, const Packet*, const Flow*);
    using SipField = DataField<const SfIp&, const DataEvent*, const Packet*, const Flow*>;
    using NumGetFn = uint64_t (*) (const DataEvent*, const Packet*, const Flow*);
    using NumField = DataField<uint64_t, const DataEvent*, const Packet*, const Flow*>;
    using NtsGetFn = struct timeval (*) (const DataEvent*, const Packet*, const Flow*);
    using NtsField = DataField<struct timeval, const DataEvent*, const Packet*, const Flow*>;

    static FlowHashKeyOps& get_hash()
    {
        static thread_local FlowHashKeyOps flow_key_ops(0);
        return flow_key_ops;
    }

    virtual std::vector<const char*> get_field_names() const;

protected:
    ExtractorEvent(uint32_t tid, ExtractorLogger& l)
        : tenant_id(tid), logger(l) {}

    template<typename T, class... Context>
    void log(const T& fields, Context... context)
    {
        for (const auto& f : fields)
            logger.add_field(f.name, f.get(context...));
    }

    uint32_t tenant_id;
    ExtractorLogger& logger;

    std::vector<NtsField> nts_fields;
    std::vector<SipField> sip_fields;
    std::vector<NumField> num_fields;
    std::vector<StrField> str_fields;
};

class HttpExtractorEventHandler : public DataHandler, public ExtractorEvent
{
public:
    using SubGetFn = const Field& (*) (const DataEvent*, const Packet*, const Flow*);
    using SubField = DataField<const Field&, const DataEvent*, const Packet*, const Flow*>;

    HttpExtractorEventHandler(uint32_t tenant, const std::vector<std::string>& flds, ExtractorLogger& l);

    void handle(DataEvent&, Flow*) override;
    std::vector<const char*> get_field_names() const override;

private:
    std::vector<SubField> sub_fields;
};

}

#endif
