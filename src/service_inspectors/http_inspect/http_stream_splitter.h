//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "stream/stream_splitter.h"

#include "http_flow_data.h"
#include "http_test_manager.h"

class HttpInspect;

class HttpStreamSplitter : public snort::StreamSplitter
{
public:
    HttpStreamSplitter(bool is_client_to_server, HttpInspect* my_inspector_) :
        snort::StreamSplitter(is_client_to_server),
        my_inspector(my_inspector_),
        source_id(is_client_to_server ? HttpEnums::SRC_CLIENT : HttpEnums::SRC_SERVER) {}
    Status scan(snort::Flow* flow, const uint8_t* data, uint32_t length, uint32_t not_used,
        uint32_t* flush_offset) override;
    const snort::StreamBuffer reassemble(snort::Flow* flow, unsigned total, unsigned, const
        uint8_t* data, unsigned len, uint32_t flags, unsigned& copied) override;
    bool finish(snort::Flow* flow) override;
    bool is_paf() override { return true; }

    // FIXIT-M should return actual packet buffer size
    unsigned max(snort::Flow*) override { return HttpEnums::MAX_OCTETS; }

private:
    void prepare_flush(HttpFlowData* session_data, uint32_t* flush_offset, HttpEnums::SectionType
        section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
        bool is_broken_chunk, uint32_t num_good_chunks, uint32_t octets_seen, bool strict_length)
        const;
    HttpCutter* get_cutter(HttpEnums::SectionType type, const HttpFlowData* session) const;
    void chunk_spray(HttpFlowData* session_data, uint8_t* buffer, const uint8_t* data,
        unsigned length) const;
    static void decompress_copy(uint8_t* buffer, uint32_t& offset, const uint8_t* data,
        uint32_t length, HttpEnums::CompressId& compression, z_stream*& compress_stream,
        bool at_start, HttpInfractions* infractions, HttpEventGen* events);

    HttpInspect* const my_inspector;
    const HttpEnums::SourceId source_id;
};

#endif

