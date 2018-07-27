//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_module.h"
#include "http2_stream_splitter.h"

class Http2Api;

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
    void show(snort::SnortConfig*) override { snort::LogMessage("Http2Inspect\n"); }
    void eval(snort::Packet* p) override;
    void clear(snort::Packet* p) override;
    Http2StreamSplitter* get_splitter(bool is_client_to_server) override
    {
        return new Http2StreamSplitter(is_client_to_server);
    }

private:
    friend Http2Api;

    const Http2ParaList* const params;
};

bool implement_get_buf(unsigned id, Http2FlowData* session_data, Http2Enums::SourceId source_id,
    snort::InspectionBuffer& b);

#endif

