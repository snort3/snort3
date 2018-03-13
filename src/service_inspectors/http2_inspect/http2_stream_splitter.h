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
// http2_stream_splitter.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_STREAM_SPLITTER_H
#define HTTP2_STREAM_SPLITTER_H

#include "stream/stream_splitter.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

class Http2Inspect;

class Http2StreamSplitter : public snort::StreamSplitter
{
public:
    Http2StreamSplitter(bool is_client_to_server) : snort::StreamSplitter(is_client_to_server),
        source_id(is_client_to_server ? Http2Enums::SRC_CLIENT : Http2Enums::SRC_SERVER) { }
    Status scan(snort::Flow* flow, const uint8_t* data, uint32_t length, uint32_t not_used,
        uint32_t* flush_offset) override;
    const snort::StreamBuffer reassemble(snort::Flow* flow, unsigned total, unsigned offset, const
        uint8_t* data, unsigned len, uint32_t flags, unsigned& copied) override;
    bool finish(snort::Flow* flow) override;
    bool is_paf() override { return true; }

    // FIXIT-M should return actual packet buffer size
    unsigned max(snort::Flow*) override { return Http2Enums::MAX_OCTETS; }

private:
    const Http2Enums::SourceId source_id;
};

snort::StreamSplitter::Status implement_scan(Http2FlowData* session_data, const uint8_t* data,
    uint32_t length, uint32_t* flush_offset, Http2Enums::SourceId source_id);
const snort::StreamBuffer implement_reassemble(Http2FlowData* session_data, unsigned total,
    unsigned offset, const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied,
    Http2Enums::SourceId source_id);

#endif

