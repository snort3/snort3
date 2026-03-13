//--------------------------------------------------------------------------
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
//--------------------------------------------------------------------------
// http_compress_stream.h author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifndef HTTP_COMPRESS_STREAM_H
#define HTTP_COMPRESS_STREAM_H

#include <optional>
#include <zlib.h>

#include "http_enum.h"
#include "http_event.h"

class HttpCompressStream
{
public:
    HttpCompressStream();
    HttpCompressStream(const HttpCompressStream& other) = delete;
    HttpCompressStream& operator=(const HttpCompressStream& other) = delete;
    HttpCompressStream(HttpCompressStream&& other) = delete;
    HttpCompressStream& operator=(HttpCompressStream&& other) = delete;
    ~HttpCompressStream();

    bool setup(HttpEnums::CompressId compression);

    std::optional<std::uint32_t> decompress(const uint8_t* src, uint32_t src_size,
        uint8_t* dst, uint32_t& dst_size, bool at_start,
        HttpInfractions* const infractions, HttpEventGen* const events);

    void copy_compressed(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size);
    static void copy_raw(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size);

    HttpEnums::CompressId get_compression_id() const
    { return compression_id; }

private:
    std::optional<std::uint32_t> decompress_zlib(const uint8_t* src, uint32_t src_size,
        uint8_t* dst, uint32_t& dst_size, bool at_start,
        HttpInfractions* const infractions, HttpEventGen* const events);

    uint8_t* process_gzip_header(const uint8_t* data, uint32_t length,
        HttpInfractions* const infractions, HttpEventGen* const events);
    bool gzip_header_check_done() const;

    z_stream* compress_stream;
    uint32_t gzip_header_bytes_processed;
    HttpEnums::CompressId compression_id;
    HttpEnums::GzipVerificationState gzip_state;
};

#endif
