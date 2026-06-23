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
// http_cache_data.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_cache_data.h"

#include <algorithm>
#include <cstring>
#include <memory>

static thread_local std::unique_ptr<HttpCacheData> http_cache_data_ptr;

HttpCacheData& get_cache_data()
{
    if (!http_cache_data_ptr)
        http_cache_data_ptr = std::make_unique<HttpCacheData>();

    return *http_cache_data_ptr;
}

bool cache_data_exists()
{
    return http_cache_data_ptr != nullptr;
}

void reset_cache_data()
{
    http_cache_data_ptr.reset();
}

void clear_tmp_fields()
{
    if (!cache_data_exists())
        return;

    HttpCacheData& cache = get_cache_data();
    for (HttpTmpBuffer& slot : cache.tmp_bufs)
    {
        slot.field.reset();
        slot.text.clear();
        slot.num = 0;
    }
    cache.decoded_path.reset();
}

void HttpRequestScratch::save_request_line(const uint8_t* data, uint32_t len)
{
    for (uint32_t i = 0; i + 1 < len; ++i)
    {
        if (data[i] == '\r' and data[i + 1] == '\n')
        {
            len = i;
            break;
        }
    }
    request_line_raw_len = static_cast<uint16_t>(
        std::min(len, static_cast<uint32_t>(MAX_REQUEST_LINE_LOG_LEN)));
    memcpy(request_line_raw.data(), data, request_line_raw_len);
}

void HttpCacheData::append_escaped(std::string& out, const uint8_t* data,
    int32_t len, int32_t max_append)
{
    static constexpr char hex_chars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    const int32_t limit = static_cast<int32_t>(out.length()) + max_append;
    for (int32_t i = 0; i < len; ++i)
    {
        const int32_t remaining = limit - static_cast<int32_t>(out.length());
        if (remaining <= 0)
            break;
        const uint8_t c = data[i];
        if (c == '\\')
        {
            if (remaining < 4)
                break;
            out.append("\\x5c");
        }
        else if (c < 0x20 || c > 0x7E)
        {
            if (remaining < 4)
                break;
            out.append("\\x");
            out.push_back(hex_chars[(c >> 4) & 0x0F]);
            out.push_back(hex_chars[c & 0x0F]);
        }
        else
            out.push_back(static_cast<char>(c));
    }
}
