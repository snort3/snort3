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

#include <cstdint>
#include <optional>

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

#include <zlib.h>

#include "http_enum.h"
#include "http_event.h"
#include "http_module.h"

namespace snort { class Flow; }

class HttpCompressStream
{
public:
    static HttpCompressStream* create(HttpEnums::CompressId compression,
        const HttpParaList::DecompressionParam& decompression_param,
        HttpInfractions* const infractions, HttpEventGen* const events,
        snort::Flow* flow = nullptr);

    virtual ~HttpCompressStream();
    HttpCompressStream(const HttpCompressStream& other) = delete;
    HttpCompressStream& operator=(const HttpCompressStream& other) = delete;
    HttpCompressStream(HttpCompressStream&& other) = delete;
    HttpCompressStream& operator=(HttpCompressStream&& other) = delete;

    virtual std::optional<uint32_t> decompress(const uint8_t* src, uint32_t src_size,
        uint8_t* dst, uint32_t& dst_size, bool at_start,
        HttpInfractions* const infractions, HttpEventGen* const events) = 0;

    HttpEnums::CompressId get_compression_id() const { return compression_id; }

    void copy_compressed(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size) const;
    static void copy_raw(const uint8_t* src, uint32_t src_size, uint8_t* dst, uint32_t& dst_size);

protected:
    HttpCompressStream(HttpEnums::CompressId id, int32_t max_expansion_ratio, snort::Flow* flow)
        : compression_id(id), max_expansion_ratio(max_expansion_ratio), owner_flow(flow)
    { }

    bool is_high_expansion(size_t consumed, size_t produced) const;

    // Library-internal allocations (zlib inflate window, brotli decoder state)
    // are routed through these via the libs' allocator hooks. Each block stores
    // its size in a header so the free hook can recover the exact amount from
    // the pointer alone.
    void* track_alloc(size_t bytes);
    void track_free(void* address);

    // Subclass ctor records the wrapper object plus any fixed sub-allocation
    // it owns directly (e.g. zlib's z_stream); the base dtor releases it.
    void account_fixed_footprint(size_t bytes);

    HttpEnums::CompressId compression_id;
    const int32_t max_expansion_ratio;
    snort::Flow* const owner_flow;
    size_t fixed_footprint = 0;
};

class ZlibStream : public HttpCompressStream
{
public:
    ZlibStream(HttpEnums::CompressId id, int32_t max_ratio, snort::Flow* flow);
    ZlibStream(const ZlibStream& other) = delete;
    ZlibStream& operator=(const ZlibStream& other) = delete;
    ZlibStream(ZlibStream&& other) = delete;
    ZlibStream& operator=(ZlibStream&& other) = delete;
    ~ZlibStream() override;

    bool init();

    std::optional<uint32_t> decompress(const uint8_t* src, uint32_t src_size,
        uint8_t* dst, uint32_t& dst_size, bool at_start,
        HttpInfractions* const infractions, HttpEventGen* const events) override;

private:
    static void* zlib_alloc(void* opaque, unsigned items, unsigned size);
    static void zlib_free(void* opaque, void* address);

    uint8_t* process_gzip_header(const uint8_t* data, uint32_t length,
        HttpInfractions* const infractions, HttpEventGen* const events);
    bool gzip_header_check_done() const;

    z_stream* compress_stream;
    uint32_t gzip_header_bytes_processed;
    HttpEnums::GzipVerificationState gzip_state;
    const bool gzip;
};

#ifdef HAVE_BROTLI
class BrotliStream : public HttpCompressStream
{
public:
    BrotliStream(int32_t max_ratio, snort::Flow* flow);
    BrotliStream(const BrotliStream& other) = delete;
    BrotliStream& operator=(const BrotliStream& other) = delete;
    BrotliStream(BrotliStream&& other) = delete;
    BrotliStream& operator=(BrotliStream&& other) = delete;
    ~BrotliStream() override;

    bool init();

    std::optional<uint32_t> decompress(const uint8_t* src, uint32_t src_size,
        uint8_t* dst, uint32_t& dst_size, bool at_start,
        HttpInfractions* const infractions, HttpEventGen* const events) override;

private:
    static void on_metadata_start(void* opaque, size_t size);
    static void on_metadata_chunk(void* opaque, const uint8_t* data, size_t size);

    static void* brotli_alloc(void* opaque, size_t size);
    static void brotli_free(void* opaque, void* address);

    bool drain(uint8_t* dst, uint32_t& dst_size,
        HttpInfractions* const infractions, HttpEventGen* const events);

    BrotliDecoderState* state;
    uint32_t pending;
    uint32_t produced;
};
#endif

#endif
