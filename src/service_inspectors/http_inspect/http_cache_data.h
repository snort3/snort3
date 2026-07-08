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
#include <string>

#include "http_enum.h"
#include "http_field.h"

static constexpr int32_t MAX_REQUEST_LINE_LOG_LEN = 256;
static constexpr int32_t HX_REQUEST_LINE_SUFFIX_LEN =
    static_cast<int32_t>(sizeof(" HTTP/1.1")) - 1;
static constexpr unsigned HTTP_FIRST_TMP_BUFFER = HttpEnums::HTTP__BUFFER_MAX + 1;
static constexpr unsigned HTTP_TMP_BUFFER_CNT =
    HttpEnums::HTTP__TMP_BUFFER_MAX - HttpEnums::HTTP__BUFFER_MAX;

struct HttpRequestScratch
{
    HttpEnums::GenericEventReasonCode reason_code_detail_300 =
        HttpEnums::GenericEventReasonCode::NONE;
    uint32_t request_size = 0;
    uint32_t request_line_length = 0;
    uint32_t hx_request_line_length = 0;

    // Raw (unescaped) request line bytes, copied only for the rare splitter-generated
    // EVENT_REQUEST_LINE_NOT_VALID paths where no HttpMsgRequest exists yet.
    std::array<uint8_t, MAX_REQUEST_LINE_LOG_LEN> request_line_raw = {};
    uint16_t request_line_raw_len = 0;

    void save_request_line(const uint8_t* data, uint32_t len);
};

struct HttpTmpBuffer
{
    Field field;
    std::string text;
    uint32_t num = 0;
};

class HttpCacheData
{
public:
    HttpCacheData() = default;
    HttpCacheData(const HttpCacheData&) = delete;
    HttpCacheData& operator=(const HttpCacheData&) = delete;

    HttpRequestScratch request;
    HttpEnums::Detail301ReasonCode reason_code_detail_301[2] = { HttpEnums::DETAIL_301_NONE,
        HttpEnums::DETAIL_301_NONE };
    std::array<HttpTmpBuffer, HTTP_TMP_BUFFER_CNT> tmp_bufs;

    // Sidecar for decoded URI path (paired with HTTP_BUFFER_DECODED_URI slot).
    Field decoded_path;

    static void append_escaped(std::string& out, const uint8_t* data,
        int32_t len, int32_t max_append);
};

HttpCacheData& get_cache_data();
bool cache_data_exists();
void reset_cache_data();
void clear_tmp_fields();


#endif
