//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// file_mime_decode.h author Bhagya Bantwal <bbantwal@cisco.com>

#ifndef FILE_MIME_DECODE_H
#define FILE_MIME_DECODE_H

// Email attachment decoder, supports Base64, QP, UU, and Bit7/8

#include "decompress/file_decomp.h"
#include "framework/counts.h"
#include "helpers/buffer_data.h"
#include "main/snort_types.h"
#include "mime/decode_base.h"
#include "mime/file_mime_config.h"

namespace snort
{

enum DecodeType
{
    DECODE_NONE = 0,
    DECODE_BITENC,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
};

struct MimeStats
{
    PegCount b64_attachments;
    PegCount b64_bytes;
    PegCount qp_attachments;
    PegCount qp_bytes;
    PegCount uu_attachments;
    PegCount uu_bytes;
    PegCount bitenc_attachments;
    PegCount bitenc_bytes;
};

class SO_PUBLIC MimeDecode
{
public:
    MimeDecode(const snort::DecodeConfig* conf);
    ~MimeDecode();

    // get the decode type from buffer
    void process_decode_type(const char* start, int length);
    void finalize_decoder(MimeStats* mime_stats);

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end);

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(const uint8_t** buf,  uint32_t* size);

    int get_detection_depth();

    void clear_decode_state();
    void reset_decoded_bytes();

    DecodeType get_decode_type();

    void file_decomp_reset();
    void file_decomp_init();

    DecodeResult decompress_data(const uint8_t* buf_in, uint32_t size_in,
                                 const uint8_t*& buf_out, uint32_t& size_out);
    const BufferData& _get_ole_buf();
    const BufferData& get_decomp_vba_data();
    void clear_decomp_vba_data();

    static void init();

private:
    void get_ole_data();
    DecodeType decode_type = DECODE_NONE;
    const snort::DecodeConfig* config;
    DataDecode* decoder = nullptr;
    fd_session_t* fd_state = nullptr;
    BufferData ole_data;
    BufferData decompressed_vba_data;
};

} // namespace snort

#endif

