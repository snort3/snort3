//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_stream.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_stream.h"

using namespace HttpCommon;

Http2Stream::Http2Stream(Http2FlowData* session_data_) : session_data(session_data_)
{
}

Http2Stream::~Http2Stream()
{
    delete current_frame;
}

void Http2Stream::eval_frame(const uint8_t* header_buffer, int32_t header_len,
    const uint8_t* data_buffer, int32_t data_len, SourceId source_id)
{
    delete current_frame;
    current_frame = Http2Frame::new_frame(header_buffer, header_len, data_buffer,
        data_len, session_data, source_id);
}

void Http2Stream::clear_frame()
{
    delete current_frame;
    current_frame = nullptr;
}

const Field& Http2Stream::get_buf(unsigned id)
{
    if (current_frame != nullptr)
        return current_frame->get_buf(id);
    return Field::FIELD_NULL;
}

#ifdef REG_TEST
void Http2Stream::print_frame(FILE* output)
{
    if (current_frame != nullptr)
        current_frame->print_frame(output);
}
#endif

