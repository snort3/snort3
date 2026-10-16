//---------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
//---------------------------------------------------------------------------
// http_field_buffer.h author Cisco

#ifndef HTTP_FIELD_BUFFER_H
#define HTTP_FIELD_BUFFER_H

#include <cstdint>
#include <string>

#include "http_buffer_info.h"
#include "http_field.h"

class HttpMsgSection;
struct HttpSplitterSnapshot;

const Field& get_http_tmp_buffer(const HttpBufferInfo& buf, HttpMsgSection* section);

const Field& get_http_tmp_buffer(const HttpBufferInfo& buf,
    const HttpSplitterSnapshot* snap_300, const HttpSplitterSnapshot* snap_299,
    const HttpSplitterSnapshot* snap_298);

bool is_wire_reportable_buffer(unsigned buf_type);

void append_escaped(std::string& out, const uint8_t* data, int32_t len, int32_t max_append);

// Appends a header line, replacing the value of a credential-bearing header with a placeholder.
void append_header_detail(std::string& out, const uint8_t* data, int32_t len, int32_t max_append);

#endif
