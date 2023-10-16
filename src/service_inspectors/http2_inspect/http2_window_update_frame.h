//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// http2_window_update_frame.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_WINDOW_UPDATE_FRAME_H
#define HTTP2_WINDOW_UPDATE_FRAME_H

#include "http2_frame.h"

class Http2Frame;

class Http2WindowUpdateFrame : public Http2Frame
{
public:
    friend Http2Frame* Http2Frame::new_frame(const uint8_t*, const uint32_t, const uint8_t*,
        const uint32_t, Http2FlowData*, HttpCommon::SourceId, Http2Stream* stream);
    bool is_detection_required() const override { return false; }
    bool valid_sequence(Http2Enums::StreamState state) override;

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

private:
    Http2WindowUpdateFrame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* stream);
};

#endif
