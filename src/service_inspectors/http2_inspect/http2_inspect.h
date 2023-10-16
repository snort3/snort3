//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
// http2_inspect.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_INSPECT_H
#define HTTP2_INSPECT_H

//-------------------------------------------------------------------------
// Http2Inspect class
//-------------------------------------------------------------------------

#include "log/messages.h"
#include "service_inspectors/http_inspect/http_common.h"

#include "http2_enum.h"
#include "http2_module.h"
#include "http2_stream_splitter.h"

class Http2Api;
class Http2FlowData;

class Http2Inspect : public snort::Inspector
{
public:
    Http2Inspect(const Http2ParaList* params_);
    ~Http2Inspect() override { delete params; }

    bool get_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p, snort::InspectionBuffer& b) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;
    bool get_fp_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet* p) override;
    void clear(snort::Packet* p) override;

    Http2StreamSplitter* get_splitter(bool is_client_to_server) override
    { return &splitter[is_client_to_server ? HttpCommon::SRC_CLIENT : HttpCommon::SRC_SERVER]; }

    bool can_carve_files() const override
    { return true; }

    const uint8_t* adjust_log_packet(snort::Packet* p, uint16_t& length) override;
private:
    friend Http2Api;

    Http2StreamSplitter splitter[2] = { true, false };

    const Http2ParaList* const params;
};

bool implement_get_buf(unsigned id, Http2FlowData* session_data, HttpCommon::SourceId source_id,
    snort::InspectionBuffer& b);
void implement_eval(Http2FlowData* session_data, HttpCommon::SourceId source_id);

#endif

