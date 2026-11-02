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
// http_cache_data.h author Cisco

#ifndef HTTP_CACHE_DATA_H
#define HTTP_CACHE_DATA_H

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "http_enum.h"
#include "http_field.h"

static constexpr int32_t MAX_REQUEST_LINE_LOG_LEN = 256;
static constexpr int32_t HX_REQUEST_LINE_SUFFIX_LEN = static_cast<int32_t>(sizeof(" HTTP/1.1")) - 1;
static constexpr unsigned HTTP_FIRST_TMP_BUFFER = HttpEnums::HTTP__BUFFER_MAX + 1;
static constexpr unsigned HTTP_TMP_BUFFER_CNT =
    HttpEnums::HTTP__TMP_BUFFER_MAX - HttpEnums::HTTP__BUFFER_MAX;

template<unsigned BUFFER_TYPE>
constexpr unsigned get_tmp_buffer_index()
{
    constexpr unsigned index = BUFFER_TYPE - HTTP_FIRST_TMP_BUFFER;
    static_assert(index < HTTP_TMP_BUFFER_CNT);
    return index;
}

struct HttpTmpBuffer
{
    void clear()
    {
        field.reset();
        text.clear();
        num = 0;
    }

    Field field;
    std::string text;
    uint32_t num = 0;
};

struct HttpTmpBufferCache
{
    void clear()
    {
        for (auto& slot : tmp_bufs)
        {
            if (slot)
                slot->clear();
        }
        decoded_path.reset();
        long_value_header.reset();
        unsafe_header.reset();
        malformed_header.reset();
    }

    std::array<std::unique_ptr<HttpTmpBuffer>, HTTP_TMP_BUFFER_CNT> tmp_bufs;

    // Sidecar for decoded URI path (paired with HTTP_BUFFER_DECODED_URI slot).
    Field decoded_path;

    // Raw header line used to materialize DETAIL_119_302.
    Field long_value_header;

    // Raw header line used to materialize DETAIL_119_304.
    Field unsafe_header;

    // Raw header line used to materialize DETAIL_119_305.
    Field malformed_header;
};

#endif
