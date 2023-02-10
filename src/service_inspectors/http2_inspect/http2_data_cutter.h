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
// http2_data_cutter.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_DATA_CUTTER_H
#define HTTP2_DATA_CUTTER_H

#include "service_inspectors/http_inspect/http_common.h"
#include "stream/stream_splitter.h"

#include "http2_enum.h"

class Http2FlowData;
class Http2Stream;

class Http2DataCutter
{
public:
    Http2DataCutter(Http2FlowData* flow_data, HttpCommon::SourceId src_id);
    snort::StreamSplitter::Status scan(const uint8_t* data, uint32_t length,
        uint32_t* flush_offset, uint32_t& data_offset, uint8_t frame_flags);
    void reassemble(const uint8_t* data, unsigned len);
    void discarded_frame_cleanup(Http2Stream* const stream);

private:
    bool check_http_state(Http2Stream* const stream);
    snort::StreamSplitter::Status skip_over_frame(Http2Stream* const stream, uint32_t length,
        uint32_t* flush_offset, uint32_t data_offset, uint8_t frame_flags);
    
    Http2FlowData* const session_data;
    const HttpCommon::SourceId source_id;

    // total per frame - scan
    uint32_t data_len;
    // accumulating - scan
    uint32_t frame_bytes_seen = 0;
    uint32_t bytes_sent_http = 0;
    uint32_t data_bytes_read;
    // total per frame - reassemble
    uint32_t reassemble_data_len;
    // accumulating - reassemble
    uint32_t reassemble_bytes_sent = 0;
    uint32_t reassemble_hdr_bytes_read = 0;
    uint32_t reassemble_data_bytes_read = 0;

    // reassemble
    enum ReassembleState { GET_FRAME_HDR, GET_PADDING_LEN, SEND_EMPTY_DATA, SEND_DATA };
    enum ReassembleState reassemble_state = GET_FRAME_HDR;
};

#endif

