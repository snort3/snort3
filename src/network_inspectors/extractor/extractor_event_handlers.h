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

#include "flow/flow_key.h"
#include "framework/data_bus.h"

#include "extractor.h"
#include "extractor_logger.h"

namespace snort
{

class ExtractorEvent
{
public:
    static FlowHashKeyOps& get_hash()
    {
        static thread_local FlowHashKeyOps flow_key_ops(0);
        return flow_key_ops;
    }

protected:
    ExtractorEvent(uint32_t tid, const std::vector<std::string>& flds, ExtractorLogger& l)
        : tenant_id(tid), fields(flds), logger(l) {}

    uint32_t tenant_id;
    const std::vector<std::string> fields;
    ExtractorLogger& logger;
};

class HttpExtractorEventHandler : public DataHandler, public ExtractorEvent
{
public:
    HttpExtractorEventHandler(uint32_t tenant, const std::vector<std::string>& flds,
        ExtractorLogger& l) : DataHandler(S_NAME), ExtractorEvent(tenant, flds, l) {}

    void handle(DataEvent&, Flow*) override;
};

}
#endif
