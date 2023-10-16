//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_stream_splitter.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_STREAM_SPLITTER_H
#define HTTP_STREAM_SPLITTER_H

#include <zlib.h>

#include "http_common.h"
#include "http_enum.h"
#include "http_flow_data.h"
#include "http_stream_splitter_base.h"
#include "http_test_manager.h"

class HttpInspect;

class HttpStreamSplitter : public HttpStreamSplitterBase
{
public:
    HttpStreamSplitter(bool is_client_to_server, HttpInspect* my_inspector_) :
        HttpStreamSplitterBase(is_client_to_server),
        my_inspector(my_inspector_),
        source_id(is_client_to_server ? HttpCommon::SRC_CLIENT : HttpCommon::SRC_SERVER) {}
    Status scan(snort::Packet* pkt, const uint8_t* data, uint32_t length, uint32_t not_used,
        uint32_t* flush_offset) override;
    Status scan(snort::Flow* flow, const uint8_t* data, uint32_t length, uint32_t* flush_offset) override;
    const snort::StreamBuffer reassemble(snort::Flow* flow, unsigned total, unsigned, const
        uint8_t* data, unsigned len, uint32_t flags, unsigned& copied) override;
    bool finish(snort::Flow* flow) override;
    void prep_partial_flush(snort::Flow* flow, uint32_t num_flush) override;
    bool is_paf() override { return true; }
    static StreamSplitter::Status status_value(StreamSplitter::Status ret_val, bool http2 = false);

    // FIXIT-M should return actual packet buffer size
    unsigned max(snort::Flow*) override { return HttpEnums::MAX_OCTETS; }
    void go_away() override {}

private:
    void prepare_flush(HttpFlowData* session_data, uint32_t* flush_offset, HttpCommon::SectionType
        section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
        bool is_broken_chunk, uint32_t num_good_chunks, uint32_t octets_seen)
        const;
    HttpCutter* get_cutter(HttpCommon::SectionType type, HttpFlowData* session) const;
    void chunk_spray(HttpFlowData* session_data, uint8_t* buffer, const uint8_t* data,
        unsigned length) const;
    void decompress_copy(uint8_t* buffer, uint32_t& offset, const uint8_t* data,
        uint32_t length, HttpEnums::CompressId& compression, z_stream*& compress_stream,
        bool at_start, HttpInfractions* infractions, HttpEventGen* events,
        HttpFlowData* session_data) const;
    void process_gzip_header(const uint8_t* data,
        uint32_t length, HttpFlowData* session_data) const;
    bool gzip_header_check_done(HttpFlowData* session_data) const;

    HttpInspect* const my_inspector;
    const HttpCommon::SourceId source_id;
};

#endif

