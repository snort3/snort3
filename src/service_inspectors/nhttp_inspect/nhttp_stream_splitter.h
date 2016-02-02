//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_stream_splitter.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_STREAM_SPLITTER_H
#define NHTTP_STREAM_SPLITTER_H

#include <zlib.h>

#include "stream/stream_splitter.h"

#include "nhttp_flow_data.h"
#include "nhttp_test_manager.h"

class NHttpInspect;

class NHttpStreamSplitter : public StreamSplitter
{
public:
    NHttpStreamSplitter(bool is_client_to_server, NHttpInspect* my_inspector_) :
        StreamSplitter(is_client_to_server),
        source_id(is_client_to_server ? NHttpEnums::SRC_CLIENT : NHttpEnums::SRC_SERVER),
        my_inspector(my_inspector_) { }
    Status scan(Flow* flow, const uint8_t* data, uint32_t length, uint32_t not_used,
        uint32_t* flush_offset) override;
    const StreamBuffer* reassemble(Flow* flow, unsigned total, unsigned, const
        uint8_t* data, unsigned len, uint32_t flags, unsigned& copied) override;
    bool finish(Flow* flow) override;
    bool is_paf() override { return true; }
    unsigned max(Flow*) override { return NHttpEnums::MAX_OCTETS; }

private:
    void prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset, NHttpEnums::SectionType
        section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
        bool is_broken_chunk, uint32_t num_good_chunks) const;
    NHttpCutter* get_cutter(NHttpEnums::SectionType type, const NHttpFlowData* session) const;
    void chunk_spray(NHttpFlowData* session_data, uint8_t* buffer, const uint8_t* data,
        unsigned length) const;
    static void decompress_copy(uint8_t* buffer, uint32_t& offset, const uint8_t* data,
        uint32_t length, NHttpEnums::CompressId& compression, z_stream*& compress_stream,
        bool at_start, NHttpInfractions& infractions, NHttpEventGen& events);

    const NHttpEnums::SourceId source_id;
    NHttpInspect* const my_inspector;
};

#endif

