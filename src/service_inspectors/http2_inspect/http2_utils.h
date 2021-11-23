//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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
// http2_utils.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_UTILS_H
#define HTTP2_UTILS_H

#include "main/snort_types.h"
#include "service_inspectors/http_inspect/http_common.h"

#include "http2_flow_data.h"

// Frame header parsing utils.
// Assumption is that if input isn't null, it contains full frame header

uint32_t get_frame_length(const uint8_t* frame_header_buffer);
uint8_t get_frame_type(const uint8_t* frame_header_buffer);
uint8_t get_frame_flags(const uint8_t* frame_header_buffer);
uint32_t get_stream_id_from_header(const uint8_t* frame_header_buffer);
uint32_t get_stream_id_from_buffer(const uint8_t* buffer);

#endif
