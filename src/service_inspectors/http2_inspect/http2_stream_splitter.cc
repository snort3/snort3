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
// http2_stream_splitter.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "http2_stream_splitter.h"
#include "http2_module.h"

using namespace snort;
using namespace Http2Enums;

// Mindless scan() that just flushes whatever it is given
StreamSplitter::Status Http2StreamSplitter::scan(Flow* flow, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    // This is the session state information we share with Http2Inspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
    {
        flow->set_flow_data(session_data = new Http2FlowData);
        Http2Module::increment_peg_counts(PEG_FLOW);
    }

    return implement_scan(session_data, data, length, flush_offset, source_id);
}

// Generic reassemble() copies the inputs unchanged into a static buffer
const StreamBuffer Http2StreamSplitter::reassemble(Flow* flow, unsigned total, unsigned offset,
    const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(session_data != nullptr);

    return implement_reassemble(session_data, total, offset, data, len, flags, copied, source_id);
}

// Eventually we will need to address unexpected connection closes
bool Http2StreamSplitter::finish(Flow* /*flow*/) { return false; }

