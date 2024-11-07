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
// extractor_flow_data.h author Cisco

#ifndef EXTRACTOR_FLOW_DATA_H
#define EXTRACTOR_FLOW_DATA_H

#include "flow/flow.h"
#include "flow/flow_data.h"

#include "extractor_enums.h"

class ExtractorFlowData : public snort::FlowData
{
public:
    ~ExtractorFlowData() override {}

    template<typename T>
    static T* get(snort::Flow* f)
    {
        auto fd = reinterpret_cast<ExtractorFlowData*>(f->get_flow_data(data_id));

        if (fd and T::type_id == fd->type)
            return reinterpret_cast<T*>(fd);

        f->free_flow_data(data_id);

        return nullptr;
    }

protected:
    ExtractorFlowData(ServiceType type, snort::Inspector& insp)
        : FlowData(data_id, &insp), type(type) {}

private:
    const ServiceType type;
    static const unsigned data_id;
};

#endif
