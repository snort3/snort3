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
// http_compress_stream.cc author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_compress_stream.h"

#include "http_common.h"
#include "http_module.h"

using namespace HttpEnums;
using namespace HttpCommon;

HttpCompressStream::HttpCompressStream()
    : compress_stream { nullptr }
    , gzip_header_bytes_processed { 0 }
    , compression_id { CMP_NONE }
    , gzip_state { GZIP_TBD }
{ }

HttpCompressStream::~HttpCompressStream()
{
    if ( compress_stream == nullptr )
        return;

    inflateEnd(compress_stream);
    delete compress_stream;

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: zlib cleared\n");
}

bool HttpCompressStream::setup(HttpEnums::CompressId compression)
{
    if ( compress_stream != nullptr )
    {
        assert(false);

        compression_id = CMP_NONE;
        delete compress_stream;
        compress_stream = nullptr;

        return false;
    }

    compression_id = compression;

    switch ( compression )
    {
    case CMP_DEFLATE:
    case CMP_GZIP:
        compress_stream = new z_stream;

        compress_stream->zalloc = Z_NULL;
        compress_stream->zfree = Z_NULL;
        compress_stream->opaque = Z_NULL;
        compress_stream->next_in = Z_NULL;
        compress_stream->avail_in = 0;

        if ( const int window_bits = compression == CMP_GZIP ? GZIP_WINDOW_BITS : DEFLATE_WINDOW_BITS;
            inflateInit2(compress_stream, window_bits) == Z_OK )
        {
            debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: zlib setup is successful\n");

            return true;
        }

        assert(false);

        compression_id = CMP_NONE;
        delete compress_stream;
        compress_stream = nullptr;

        return false;
    default:
        assert(false);

        compression_id = CMP_NONE;

        return false;
    }
}

std::optional<uint32_t> HttpCompressStream::decompress(const uint8_t* src, uint32_t src_size,
    uint8_t* dst, uint32_t& dst_size, bool at_start,
    HttpInfractions* infractions, HttpEventGen* const events)
{
    switch ( get_compression_id() )
    {
    case CMP_NONE:
        return std::nullopt;
    case CMP_DEFLATE:
    case CMP_GZIP:
        return decompress_zlib(src, src_size, dst, dst_size,
            at_start, infractions, events);
    default:
        assert(false);
        return std::nullopt;
    }
}

uint8_t* HttpCompressStream::process_gzip_header(const uint8_t* data, uint32_t length,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    uint32_t input_bytes_processed = 0;
    uint8_t* modified_data = nullptr;

    if ( gzip_state == GZIP_TBD )
    {
        static constexpr uint8_t gzip_magic[] = { 0x1f, 0x8b, 0x08 };
        static constexpr uint8_t magic_length = 3;

        const uint32_t magic_cmp_len = (magic_length - gzip_header_bytes_processed) < length ?
            (magic_length - gzip_header_bytes_processed) : length;

        if ( memcmp(data, gzip_magic + gzip_header_bytes_processed, magic_cmp_len) != 0 )
            gzip_state = GZIP_MAGIC_BAD;
        else if ( gzip_header_bytes_processed + length >= magic_length )
            gzip_state = GZIP_MAGIC_GOOD;

        gzip_header_bytes_processed += magic_cmp_len;
        input_bytes_processed += magic_cmp_len;
    }

    if ( gzip_state == GZIP_MAGIC_GOOD and length > input_bytes_processed )
    {
        const uint8_t gzip_flags = data[input_bytes_processed];

        if ( gzip_flags & GZIP_FLAG_FEXTRA )
        {
            *infractions += INF_GZIP_FEXTRA;
            events->create_event(EVENT_GZIP_FEXTRA);
        }

        if ( gzip_flags & GZIP_RESERVED_FLAGS )
        {
            *infractions += INF_GZIP_RESERVED_FLAGS;
            events->create_event(EVENT_GZIP_RESERVED_FLAGS);

            modified_data = new uint8_t[length];
            memcpy(modified_data, data, length);
            modified_data[input_bytes_processed] &= ~GZIP_RESERVED_FLAGS;
        }

        gzip_header_bytes_processed++;
        gzip_state = GZIP_FLAGS_PROCESSED;
    }

    return modified_data;
}

bool HttpCompressStream::gzip_header_check_done() const
{
    return gzip_state == HttpEnums::GZIP_MAGIC_BAD or
           gzip_state == HttpEnums::GZIP_FLAGS_PROCESSED;
}

std::optional<std::uint32_t> HttpCompressStream::decompress_zlib(const uint8_t* src, uint32_t src_size,
    uint8_t* dst, uint32_t& dst_size, bool at_start,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    uint8_t* data_w_updated_hdr = nullptr;

    if ( get_compression_id() == CMP_GZIP and !gzip_header_check_done() )
        data_w_updated_hdr = process_gzip_header(src, src_size, infractions, events);

    if ( data_w_updated_hdr != nullptr )
        compress_stream->next_in = const_cast<Bytef*>(data_w_updated_hdr);
    else
        compress_stream->next_in = const_cast<Bytef*>(src);

    compress_stream->avail_in = src_size;
    compress_stream->next_out = dst + dst_size;
    compress_stream->avail_out = MAX_OCTETS - dst_size;

    const int result = inflate(compress_stream, Z_SYNC_FLUSH);

    delete[] data_w_updated_hdr;

    switch ( result )
    {
    case Z_OK:
    case Z_STREAM_END:
        dst_size = MAX_OCTETS - compress_stream->avail_out;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompressed %u/%u, used %u/%u\n",
            src_size - compress_stream->avail_in, src_size, dst_size, MAX_OCTETS);

        if ( compress_stream->avail_in > 0 )
        {
            if ( result == Z_STREAM_END )
            {
                // The zipped data stream ended but there is more input data
                if ( get_compression_id() == CMP_GZIP )
                {
                    *infractions += INF_GZIP_EARLY_END;
                    events->create_event(EVENT_GZIP_EARLY_END);
                }
                else
                {
                    *infractions += INF_DEFLATE_EARLY_END;
                    events->create_event(EVENT_DEFLATE_EARLY_END);
                }

                const uInt num_copy = (compress_stream->avail_in <= compress_stream->avail_out) ?
                    compress_stream->avail_in : compress_stream->avail_out;

                memcpy(dst + dst_size, src + (src_size - compress_stream->avail_in), num_copy);
                dst_size += num_copy;

                debug_logf(http_trace, TRACE_COMPRESS, nullptr,
                    "Compress: compressed data ended, copied %u, used %u/%u\n", num_copy, dst_size, MAX_OCTETS);

                compress_stream->avail_in -= num_copy;
                compression_id = CMP_NONE;
            }
            else
            {
                assert(compress_stream->avail_out == 0);

                // The data expanded too much
                debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: data caused buffer to overrun\n");
            }

            // FIXIT-E - Will need to clear gzip header processing state here when we implement
            // processing multiple gzip members in a message section
        }

        return compress_stream->avail_in;
    case Z_DATA_ERROR:
        if ( get_compression_id() == CMP_DEFLATE and at_start )
        {
            // Some incorrect implementations of deflate don't use the expected header. Feed a
            // dummy header to zlib and retry the inflate.
            static constexpr uint8_t zlib_header[2] = { 0x78, 0x01 };

            inflateReset(compress_stream);

            compress_stream->next_in = const_cast<Bytef*>(zlib_header);
            compress_stream->avail_in = sizeof(zlib_header);

            const int ret = inflate(compress_stream, Z_SYNC_FLUSH);

            if ( ret == Z_OK or ret == Z_STREAM_END )
            {
                debug_log(http_trace, TRACE_COMPRESS, nullptr, "Compress: deflate header substituted\n");

                // Start over at the beginning
                const auto decompressed = decompress_zlib(src, src_size, dst, dst_size, false, infractions, events);

                if ( decompressed )
                    HttpModule::increment_peg_counts(PEG_INCORRECT_DEFLATE_HEADER);

                return decompressed;
            }

            assert(false);
            return std::nullopt;
        }

        [[fallthrough]];
    default:
        if ( get_compression_id() == CMP_GZIP )
        {
            *infractions += INF_GZIP_FAILURE;
            events->create_event(EVENT_GZIP_FAILURE);
            HttpModule::increment_peg_counts(PEG_COMPRESSED_GZIP_FAILED);
        }
        else
        {
            *infractions += INF_DEFLATE_FAILURE;
            events->create_event(EVENT_DEFLATE_FAILURE);
            HttpModule::increment_peg_counts(PEG_COMPRESSED_DEFLATE_FAILED);
        }

        compression_id = CMP_NONE;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompress failed, %s\n",
            compress_stream->msg ? compress_stream->msg : "unknown error");

        return std::nullopt;
    }
}

void HttpCompressStream::copy_compressed(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size)
{
    copy_raw(src, src_size, dst, dst_size);

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: data copied, used %u/%u\n", dst_size, MAX_OCTETS);
}

void HttpCompressStream::copy_raw(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size)
{
    // The following precaution is necessary because mixed compressed and uncompressed data can
    // cause the buffer to overrun even though we are not decompressing right now

    if ( src_size > MAX_OCTETS - dst_size )
        src_size = MAX_OCTETS - dst_size;

    memcpy(dst + dst_size, src, src_size);
    dst_size += src_size;
}
