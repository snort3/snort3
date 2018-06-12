//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// sf_email_attach_decode.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef FILE_MIME_DECODE_H
#define FILE_MIME_DECODE_H

// Email attachment decoder, supports Base64, QP, UU, and Bit7/8

#include "framework/counts.h"
#include "mime/decode_base.h"
#include "mime/file_mime_config.h"

enum DecodeType
{
    DECODE_NONE = 0,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
    DECODE_BITENC,
    DECODE_ALL
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

class MimeDecode
{
public:
    MimeDecode(snort::DecodeConfig* conf);
    ~MimeDecode();

    // get the decode type from buffer
    // bool cnt_xf: true if there is transfer encode defined, false otherwise
    void process_decode_type(const char* start, int length, bool cnt_xf, MimeStats* mime_stats);

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end);

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(const uint8_t** buf,  uint32_t* size);

    int get_detection_depth();

    void clear_decode_state();
    void reset_decoded_bytes();

    DecodeType get_decode_type();

private:
    DecodeType decode_type = DECODE_NONE;
    snort::DecodeConfig* config;
    DataDecode* decoder = nullptr;
};

#endif

