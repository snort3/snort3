//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "http2_dummy_packet.h"
#include "http2_flow_data.h"
#include "http2_module.h"

using namespace HttpCommon;
using namespace snort;
using namespace Http2Enums;

Http2DataFrame::Http2DataFrame(const uint8_t* header_buffer, const int32_t header_len,
    const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, nullptr, 0, session_data_, source_id_, stream_),
    data_length(data_len)
{
    if ((data_len != 0) || !session_data->flushing_data[source_id])
    {
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        dummy_pkt.packet_flags = (source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        dummy_pkt.dsize = data_len;
        dummy_pkt.data = data_buffer;
        dummy_pkt.xtradata_mask = 0;
        session_data->hi->eval(&dummy_pkt);
        detection_required = dummy_pkt.is_detection_required();
        xtradata_mask = dummy_pkt.xtradata_mask;
    }
    else
    {
        detection_required = true;
        HttpFlowData* const http_flow = (HttpFlowData*)session_data_->get_hi_flow_data();
        http_flow->reset_partial_flush(source_id_);
    }
}

void Http2DataFrame::clear()
{
    Http2DummyPacket dummy_pkt;
    dummy_pkt.flow = session_data->flow;
    session_data->hi->clear(&dummy_pkt);
}

void Http2DataFrame::update_stream_state()
{
    switch (stream->get_state(source_id))
    {
        case STATE_OPEN:
            if (data_length > 0)
            {
                session_data->concurrent_files += 1;
                stream->set_state(source_id, STATE_OPEN_DATA);
                if (session_data->concurrent_files >
                    Http2Module::get_peg_counts(PEG_MAX_CONCURRENT_FILES))
                {
                    Http2Module::increment_peg_counts(PEG_MAX_CONCURRENT_FILES);
                }
            }
            if (stream->is_last_data_flush(source_id))
                stream->set_state(source_id, STATE_CLOSED);
            break;
        case STATE_OPEN_DATA:
            if (stream->is_last_data_flush(source_id))
            {
                assert(session_data->concurrent_files > 0);
                session_data->concurrent_files -= 1;
                stream->set_state(source_id, STATE_CLOSED);
            }
            break;
        default:
            // Stream state is idle or closed - this is caught in scan so should not get here
            assert(false);
    }
}

#ifdef REG_TEST
void Http2DataFrame::print_frame(FILE* output)
{
    fprintf(output, "Data frame\n");
    Http2Frame::print_frame(output);
}
#endif
