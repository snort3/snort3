//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
    const StreamBuffer* reassemble(Flow* flow, unsigned total, unsigned offset, const
        uint8_t* data, unsigned len, uint32_t flags, unsigned& copied) override;
    bool is_paf() override { return true; }
    unsigned max() override
    {
        return NHttpTestManager::use_test_input() ? NHttpEnums::DATABLOCKSIZE : paf_max;
    }

private:
    void prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset, NHttpEnums::SectionType
        section_type, bool tcp_close, uint32_t num_octets, uint32_t length, uint32_t num_excess,
        bool zero_chunk);
    NHttpSplitter* get_splitter(NHttpEnums::SectionType type) const;

    const NHttpEnums::SourceId source_id;
    NHttpInspect* const my_inspector;
    unsigned paf_max = NHttpEnums::MAXOCTETS;
};

#endif

