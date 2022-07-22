//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_headers_frame_with_startline.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame_with_startline.h"

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack.h"
#include "http2_module.h"
#include "http2_request_line.h"
#include "http2_start_line.h"
#include "http2_status_line.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2HeadersFrameWithStartline::~Http2HeadersFrameWithStartline()
{
    delete start_line_generator;
}

bool Http2HeadersFrameWithStartline::process_start_line(HttpFlowData*& http_flow, SourceId hi_source_id, Packet* p)
{
    if (session_data->abort_flow[source_id])
        return false;

    // http_inspect scan() of start line
    {
        uint32_t flush_offset;
        const StreamSplitter::Status start_scan_result =
            session_data->hi_ss[hi_source_id]->scan(session_data->flow, start_line.start(), start_line.length(),
            &flush_offset);
        if (start_scan_result != StreamSplitter::FLUSH)
        {
            stream->set_state(hi_source_id, STREAM_ERROR);
            return false;
        }
        assert((int64_t)flush_offset == start_line.length());
    }

    StreamBuffer stream_buf;

    // http_inspect reassemble() of start line
    {
        unsigned copied;
        stream_buf = session_data->hi_ss[hi_source_id]->reassemble(session_data->flow,
            start_line.length(), 0, start_line.start(), start_line.length(), PKT_PDU_TAIL,
            copied);
        assert(stream_buf.data != nullptr);
        assert(copied == (unsigned)start_line.length());
    }

    http_flow = stream->get_hi_flow_data();
    assert(http_flow);
    // http_inspect eval() and clear() of start line
    {
        session_data->hi->eval(p, hi_source_id, stream_buf.data, stream_buf.length);
        if (http_flow->get_type_expected(hi_source_id) != SEC_HEADER)
        {
            stream->set_state(hi_source_id, STREAM_ERROR);
            return false;
        }
        session_data->hi->clear(p);
    }
    return true;
}

// If we are not processing a truncated headers frame or we have seen a non-pseudoheader, we know
// we've seen all the (valid) pseudoheaders in the frame. Otherwise we could be missing some due
// to truncation
bool Http2HeadersFrameWithStartline::are_pseudo_headers_complete()
{
    return !session_data->is_processing_partial_header() or
        !hpack_decoder->are_pseudo_headers_allowed();
}

#ifdef REG_TEST
void Http2HeadersFrameWithStartline::print_frame(FILE* output)
{
    start_line.print(output, "Decoded start-line");
    Http2HeadersFrame::print_frame(output);
}
#endif
