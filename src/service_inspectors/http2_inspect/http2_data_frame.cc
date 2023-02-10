//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// http2_data_frame.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_data_frame.h"

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_flow_data.h"
#include "http2_module.h"

using namespace HttpCommon;
using namespace snort;
using namespace Http2Enums;

Http2DataFrame::Http2DataFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer_, const uint32_t data_length_, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, nullptr, 0, session_data_, source_id_, stream_),
    data_length(data_length_),
    data_buffer(data_buffer_)
{}

bool Http2DataFrame::valid_sequence(Http2Enums::StreamState state)
{
    return (state == Http2Enums::STREAM_EXPECT_BODY) || (state == Http2Enums::STREAM_BODY);
}

void Http2DataFrame::analyze_http1(Packet* p)
{
    // FIXIT-E no checks here
    session_data->hi->eval(p, source_id, data_buffer, data_length);
}

void Http2DataFrame::clear(Packet* p)
{
    session_data->hi->clear(p);
}

void Http2DataFrame::update_stream_state()
{
    switch (stream->get_state(source_id))
    {
        case STREAM_EXPECT_BODY:
            if (data_length > 0)
            {
                session_data->concurrent_files += 1;
                stream->set_state(source_id, STREAM_BODY);
                if (session_data->concurrent_files >
                    Http2Module::get_peg_counts(PEG_MAX_CONCURRENT_FILES))
                {
                    Http2Module::increment_peg_counts(PEG_MAX_CONCURRENT_FILES);
                }
            }
            if (stream->is_end_stream_on_data_flush(source_id))
            {
                if (data_length > 0)
                    session_data->concurrent_files -= 1;
                stream->set_state(source_id, STREAM_COMPLETE);
            }
            break;
        case STREAM_BODY:
            if (stream->is_end_stream_on_data_flush(source_id))
            {
                assert(session_data->concurrent_files > 0);
                session_data->concurrent_files -= 1;
                stream->set_state(source_id, STREAM_COMPLETE);
            }
            break;
        default:
            // Stream state is idle or closed - this is caught in scan so should not get here
            assert(false);
    }
}

uint8_t Http2DataFrame::get_flags_mask() const { return (FLAG_END_STREAM|FLAG_PADDED); }

#ifdef REG_TEST
void Http2DataFrame::print_frame(FILE* output)
{
    fprintf(output, "Data frame\n");
    Http2Frame::print_frame(output);
}
#endif
