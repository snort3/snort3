//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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
// file_mime_context_data.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_context_data.h"

#include "detection/detection_engine.h"
#include "file_api/file_service.h"
#include "utils/util.h"

using namespace snort;

unsigned MimeDecodeContextData::mime_ips_id = 0;

MimeDecodeContextData::MimeDecodeContextData()
{
    decode_buf = (uint8_t*)snort_alloc(MAX_DEPTH);

    decompress_buf_size = FileService::decode_conf.get_decompress_buffer_size();
    decompress_buf = (uint8_t*)snort_alloc(decompress_buf_size);
}

MimeDecodeContextData::~MimeDecodeContextData()
{
    snort_free(decode_buf);
    snort_free(decompress_buf);
    decode_buf = nullptr;
    decompress_buf = nullptr;
}

void MimeDecodeContextData::init()
{ mime_ips_id = IpsContextData::get_ips_id(); }

uint8_t* MimeDecodeContextData::get_decode_buf()
{
    MimeDecodeContextData* data = IpsContextData::get<MimeDecodeContextData>(mime_ips_id);

    return data->decode_buf;
}

uint8_t* MimeDecodeContextData::get_decompress_buf()
{
    MimeDecodeContextData* data = IpsContextData::get<MimeDecodeContextData>(mime_ips_id);

    return data->decompress_buf;
}

uint32_t MimeDecodeContextData::get_decompress_buf_size()
{
    MimeDecodeContextData* data = IpsContextData::get<MimeDecodeContextData>(mime_ips_id);

    return data->decompress_buf_size;
}

