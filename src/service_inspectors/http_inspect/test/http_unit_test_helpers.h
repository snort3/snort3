//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_unit_test_helpers.h author Maya Dagon <mdagon@cisco.com>
// Code moved from http_transaction_test.cc, author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_UNIT_TEST_HELPERS_H
#define HTTP_UNIT_TEST_HELPERS_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_compress_stream.h"
#include "service_inspectors/http_inspect/http_event.h"
#include "service_inspectors/http_inspect/http_flow_data.h"

class HttpUnitTestSetup
{
public:
    static HttpCommon::SectionType* get_section_type(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->section_type; }
    static HttpCommon::SectionType* get_type_expected(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->type_expected; }
    static void half_reset(HttpFlowData* flow_data, HttpCommon::SourceId source_id)
        { assert(flow_data!=nullptr); flow_data->half_reset(source_id); }
    static void set_compress_stream(HttpFlowData* flow_data, HttpCommon::SourceId source_id,
        HttpCompressStream* stream)
        { assert(flow_data!=nullptr); flow_data->compress[source_id] = stream; }
    static void set_partial_buffer(HttpFlowData* flow_data, HttpCommon::SourceId source_id,
        uint8_t* buf, uint32_t length)
    {
        assert(flow_data!=nullptr);
        flow_data->partial_buffer[source_id] = buf;
        flow_data->partial_buffer_length[source_id] = length;
    }
    static HttpInfractions* get_infractions(HttpFlowData* flow_data, HttpCommon::SourceId source_id)
        { assert(flow_data!=nullptr); return flow_data->infractions[source_id]; }
    static void set_partial_flush(HttpFlowData* flow_data, HttpCommon::SourceId source_id,
        bool partial_flush, uint32_t num_excess)
    {
        assert(flow_data!=nullptr);
        flow_data->partial_flush[source_id] = partial_flush;
        flow_data->num_excess[source_id] = num_excess;
    }
};

#endif
