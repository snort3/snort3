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

#include "utils/util.h"

#include "http_common.h"

using namespace HttpEnums;
using namespace HttpCommon;

bool HttpCompressStream::is_high_expansion(size_t consumed, size_t produced) const
{
    if ( max_expansion_ratio < 0 )
        return false;

    return produced > consumed * max_expansion_ratio;
}

ZlibStream::ZlibStream(CompressId id, int32_t max_ratio)
    : HttpCompressStream(id, max_ratio)
    , compress_stream { nullptr }
    , gzip_header_bytes_processed { 0 }
    , gzip_state { GZIP_TBD }
    , gzip { id == CMP_GZIP }
{
    assert(id == CMP_GZIP or id == CMP_DEFLATE);
}

bool ZlibStream::init()
{
    assert(compress_stream == nullptr);

    compress_stream = new z_stream;
    compress_stream->zalloc = Z_NULL;
    compress_stream->zfree = Z_NULL;
    compress_stream->opaque = Z_NULL;
    compress_stream->next_in = Z_NULL;
    compress_stream->avail_in = 0;

    const int window_bits = gzip ? GZIP_WINDOW_BITS : DEFLATE_WINDOW_BITS;

    if ( inflateInit2(compress_stream, window_bits) == Z_OK )
    {
        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: %s setup is successful\n",
            gzip ? "gzip" : "deflate");

        return true;
    }

    assert(false);

    delete compress_stream;
    compress_stream = nullptr;

    return false;
}

std::optional<uint32_t> ZlibStream::decompress(const uint8_t* src, uint32_t src_size,
    uint8_t* dst, uint32_t& dst_size, bool at_start,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    if ( compression_id == CMP_NONE )
        return std::nullopt;

    uint8_t* data_w_updated_hdr = nullptr;

    if ( gzip and !gzip_header_check_done() )
        data_w_updated_hdr = process_gzip_header(src, src_size, infractions, events);

    if ( data_w_updated_hdr != nullptr )
        compress_stream->next_in = const_cast<Bytef*>(data_w_updated_hdr);
    else
        compress_stream->next_in = const_cast<Bytef*>(src);

    compress_stream->avail_in = src_size;
    compress_stream->next_out = dst + dst_size;
    assert(MAX_OCTETS >= dst_size);

    compress_stream->avail_out = MAX_OCTETS - dst_size;

    const int result = inflate(compress_stream, Z_SYNC_FLUSH);

    delete[] data_w_updated_hdr;

    switch ( result )
    {
    case Z_OK:
    case Z_STREAM_END:
        if ( is_high_expansion(src_size - compress_stream->avail_in,
            MAX_OCTETS - compress_stream->avail_out - dst_size) )
        {
            if ( gzip )
            {
                *infractions += INF_GZIP_HIGH_EXPANSION;
                events->create_event(EVENT_GZIP_HIGH_EXPANSION);
            }
            else
            {
                *infractions += INF_DEFLATE_HIGH_EXPANSION;
                events->create_event(EVENT_DEFLATE_HIGH_EXPANSION);
            }

            debug_logf(http_trace, TRACE_COMPRESS, nullptr,
                "Compress: high expansion, produced %u from %u, exceeds ratio %d\n",
                MAX_OCTETS - compress_stream->avail_out - dst_size,
                src_size - compress_stream->avail_in, max_expansion_ratio);

            compression_id = CMP_NONE;
        }

        dst_size = MAX_OCTETS - compress_stream->avail_out;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompressed %u/%u, used %u/%u\n",
            src_size - compress_stream->avail_in, src_size, dst_size, MAX_OCTETS);

        if ( compress_stream->avail_in > 0 )
        {
            if ( result == Z_STREAM_END )
            {
                if ( gzip )
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
                debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: data caused buffer to overrun\n");
            }

            // FIXIT-E - Will need to clear gzip header processing state here when we implement
            // processing multiple gzip members in a message section
        }

        return compress_stream->avail_in;
    case Z_DATA_ERROR:
        if ( !gzip and at_start )
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

                const auto decompressed = decompress(src, src_size, dst, dst_size,
                    false, infractions, events);

                if ( decompressed )
                    HttpModule::increment_peg_counts(PEG_INCORRECT_DEFLATE_HEADER);

                return decompressed;
            }

            assert(false);
            return std::nullopt;
        }

        [[fallthrough]];
    default:
        if ( gzip )
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

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompress failed, %s\n",
            compress_stream->msg ? compress_stream->msg : "unknown error");

        compression_id = CMP_NONE;
        return std::nullopt;
    }
}

uint8_t* ZlibStream::process_gzip_header(const uint8_t* data, uint32_t length,
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

bool ZlibStream::gzip_header_check_done() const
{
    return gzip_state == HttpEnums::GZIP_MAGIC_BAD or
           gzip_state == HttpEnums::GZIP_FLAGS_PROCESSED;
}

ZlibStream::~ZlibStream()
{
    if ( compress_stream == nullptr )
        return;

    inflateEnd(compress_stream);
    delete compress_stream;

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: %s cleared\n",
        gzip ? "gzip" : "deflate");
}

#ifdef HAVE_BROTLI
void BrotliStream::on_metadata_start(void*, [[maybe_unused]] size_t size)
{
    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: brotli metadata start, size %zu\n", size);
}

void BrotliStream::on_metadata_chunk(void*, const uint8_t*, [[maybe_unused]] size_t size)
{
    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: brotli metadata chunk, size %zu\n", size);
}

void* BrotliStream::brotli_alloc(void*, size_t size)
{
    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: allocated %zu\n", size);
    return snort_alloc(size);
}

void BrotliStream::brotli_free(void*, void* address)
{
    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: freed memory\n");
    snort_free(address);
}

BrotliStream::BrotliStream(int32_t max_ratio)
    : HttpCompressStream(CMP_BROTLI, max_ratio)
    , state { nullptr }
    , pending { 0 }
    , produced { 0 }
{ }

BrotliStream::~BrotliStream()
{
    if ( state == nullptr )
        return;

    BrotliDecoderDestroyInstance(state);

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: brotli cleared\n");
}

bool BrotliStream::init()
{
    assert(state == nullptr);

    state = BrotliDecoderCreateInstance(brotli_alloc, brotli_free, nullptr);

    if ( state == nullptr )
    {
        assert(false);
        return false;
    }

    BrotliDecoderSetMetadataCallbacks(state, on_metadata_start, on_metadata_chunk, nullptr);

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: brotli setup is successful\n");

    return true;
}

bool BrotliStream::drain(uint8_t* dst, uint32_t& dst_size,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    while ( dst_size < MAX_OCTETS and BrotliDecoderHasMoreOutput(state) )
    {
        size_t size = MAX_OCTETS - dst_size;
        const uint8_t* data = BrotliDecoderTakeOutput(state, &size);

        if ( data == nullptr or size == 0 )
            break;

        produced += size;
        if ( is_high_expansion(pending, produced) )
        {
            events->create_event(EVENT_BROTLI_HIGH_EXPANSION);
            *infractions += INF_BROTLI_HIGH_EXPANSION;

            debug_logf(http_trace, TRACE_COMPRESS, nullptr,
                "Compress: high expansion, produced %u from %u, exceeds ratio %d\n",
                produced, pending, max_expansion_ratio);

            compression_id = CMP_NONE;
        }

        memcpy(dst + dst_size, data, size);
        dst_size += size;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr,
            "Compress: took %zu, used %u/%u\n", size, dst_size, MAX_OCTETS);
    }

    return !BrotliDecoderHasMoreOutput(state);
}

std::optional<uint32_t> BrotliStream::decompress(const uint8_t* src, uint32_t src_size,
    uint8_t* dst, uint32_t& dst_size, bool,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    assert(state != nullptr);

    if ( compression_id == CMP_NONE )
        return std::nullopt;

    if ( BrotliDecoderHasMoreOutput(state) )
    {
        const auto done = drain(dst, dst_size, infractions, events);

        if ( !done )
            return src_size;

        if ( BrotliDecoderIsFinished(state) )
            compression_id = CMP_NONE;

        const auto released = pending;
        pending = 0;
        produced = 0;
        return src_size - released;
    }

    size_t avail_in = src_size;
    const uint8_t* next_in = src;

    assert(MAX_OCTETS >= dst_size);
    size_t avail_out = MAX_OCTETS - dst_size;
    uint8_t* next_out = dst + dst_size;

    const auto result = BrotliDecoderDecompressStream(state, &avail_in, &next_in,
        &avail_out, &next_out, nullptr);

    if ( result == BROTLI_DECODER_RESULT_ERROR )
    {
        events->create_event(EVENT_BROTLI_FAILURE);
        *infractions += INF_BROTLI_FAILURE;
        HttpModule::increment_peg_counts(PEG_COMPRESSED_BROTLI_FAILED);

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompress failed, %s\n",
            BrotliDecoderErrorString(BrotliDecoderGetErrorCode(state)));

        pending = 0;
        compression_id = CMP_NONE;

        return std::nullopt;
    }

    if ( is_high_expansion(src_size - avail_in, MAX_OCTETS - avail_out - dst_size) )
    {
        events->create_event(EVENT_BROTLI_HIGH_EXPANSION);
        *infractions += INF_BROTLI_HIGH_EXPANSION;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr,
            "Compress: high expansion, produced %zu from %zu, exceeds ratio %d\n",
            MAX_OCTETS - avail_out - dst_size, src_size - avail_in, max_expansion_ratio);

        compression_id = CMP_NONE;
    }

    const uint32_t decompressed = MAX_OCTETS - avail_out - dst_size;
    dst_size = MAX_OCTETS - avail_out;

    debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: decompressed %u/%u, used %u/%u\n",
        static_cast<uint32_t>(src_size - avail_in), src_size, dst_size, MAX_OCTETS);

    if ( BrotliDecoderHasMoreOutput(state) )
    {
        pending = src_size - avail_in;
        produced = decompressed;
        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: buffered internally, pending %u\n", pending);

        return src_size;
    }

    if ( avail_in > 0 )
    {
        events->create_event(EVENT_BROTLI_EARLY_END);
        *infractions += INF_BROTLI_EARLY_END;

        const uint32_t num_copy = avail_in <= avail_out ? avail_in : avail_out;

        memcpy(dst + dst_size, src + src_size - avail_in, num_copy);
        dst_size += num_copy;

        debug_logf(http_trace, TRACE_COMPRESS, nullptr, "Compress: compressed data ended, copied %u, used %u/%u\n",
            num_copy, dst_size, MAX_OCTETS);

        compression_id = CMP_NONE;

        return avail_in - num_copy;
    }

    if ( BrotliDecoderIsFinished(state) )
        compression_id = CMP_NONE;

    return avail_in;
}

#endif

HttpCompressStream* HttpCompressStream::create(CompressId compression,
    const HttpParaList::DecompressionParam& decompression_param,
    HttpInfractions* const infractions, HttpEventGen* const events)
{
    switch ( compression )
    {
    case CMP_DEFLATE:
    case CMP_GZIP:
    {
        auto* const stream = new ZlibStream(compression, decompression_param.max_expansion_ratio);

        if ( stream->init() )
            return stream;

        delete stream;
        return nullptr;
    }
    case CMP_BROTLI:
#ifdef HAVE_BROTLI
    {
        if ( !decompression_param.decompress_brotli )
        {
            events->create_event(EVENT_BROTLI_DISABLED);
            *infractions += INF_BROTLI_DISABLED;
            return nullptr;
        }

        auto* const stream = new BrotliStream(decompression_param.max_expansion_ratio);

        if ( stream->init() )
            return stream;

        delete stream;
        return nullptr;
    }
#else
        return nullptr;
#endif
    default:
        assert(false);
        return nullptr;
    }
}

void HttpCompressStream::copy_compressed(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size) const
{
    assert(compression_id == CMP_NONE);
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
