//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_config.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_config.h"

#include "log/messages.h"
#include "file_api/file_service.h"

using namespace snort;

void DecodeConfig::set_ignore_data(bool ignored)
{
    ignore_data = ignored;
}

bool DecodeConfig::is_ignore_data() const
{
    return ignore_data;
}

void DecodeConfig::set_b64_depth(int depth)
{
    b64_depth = depth;
}

int DecodeConfig::get_b64_depth() const
{
    return b64_depth;
}

void DecodeConfig::set_qp_depth(int depth)
{
    qp_depth = depth;
}

int DecodeConfig::get_qp_depth() const
{
    return qp_depth;
}

void DecodeConfig::set_bitenc_depth(int depth)
{
    bitenc_depth = depth;
}

int DecodeConfig::get_bitenc_depth() const
{
    return bitenc_depth;
}

void DecodeConfig::set_uu_depth(int depth)
{
    uu_depth = depth;
}

int DecodeConfig::get_uu_depth() const
{
    return uu_depth;
}

void DecodeConfig::set_decompress_pdf(bool enabled)
{
    decompress_pdf = enabled;
}

bool DecodeConfig::is_decompress_pdf() const
{
    return decompress_pdf;
}

void DecodeConfig::set_decompress_swf(bool enabled)
{
    decompress_swf = enabled;
}

bool DecodeConfig::is_decompress_swf() const
{
    return decompress_swf;
}

void DecodeConfig::set_decompress_zip(bool enabled)
{
    decompress_zip = enabled;
}

bool DecodeConfig::is_decompress_zip() const
{
    return decompress_zip;
}

void DecodeConfig::set_decompress_vba(bool enabled)
{
    decompress_vba = enabled;
}

bool DecodeConfig::is_decompress_vba() const
{
    return decompress_vba;
}

void DecodeConfig::set_decompress_buffer_size(uint32_t size)
{
    decompress_buffer_size = size;
}

uint32_t DecodeConfig::get_decompress_buffer_size() const
{
    return decompress_buffer_size;
}

int64_t DecodeConfig::get_file_depth() const
{
    return file_depth;
}

bool DecodeConfig::is_decoding_enabled() const
{
    return decode_enabled;
}

// update file depth and max_depth etc
void DecodeConfig::sync_all_depths()
{
    file_depth = FileService::get_max_file_depth();
    decode_enabled = (file_depth >= 0) or (b64_depth >= 0) or (qp_depth >= 0) or
        (bitenc_depth >= 0) or (uu_depth >= 0);
}

int DecodeConfig::get_max_depth(int decode_depth) const
{
    if ( file_depth and decode_depth )
        return (file_depth > decode_depth) ? file_depth : decode_depth;

    return 0;
}

//FIXIT-L update this after mime decode depths are revisited
void DecodeConfig::show(bool full) const
{
    if ( !decode_enabled )
    {
        ConfigLogger::log_flag("decode_enabled", decode_enabled);
        return;
    }

    auto b64 = (b64_depth == 0) ? -1 : ((b64_depth == -1) ? 0 : b64_depth);
    auto qp = (qp_depth == 0) ? -1 : ((qp_depth == -1) ? 0 : qp_depth);
    auto uu = (uu_depth == 0) ? -1 : ((uu_depth == -1) ? 0 : uu_depth);
    auto bitenc = (bitenc_depth == 0) ? -1 : ((bitenc_depth == -1) ? 0 : bitenc_depth);
    ConfigLogger::log_limit("b64_decode_depth", b64, -1, 0);
    ConfigLogger::log_limit("qp_decode_depth", qp, -1, 0);
    ConfigLogger::log_limit("uu_decode_depth", uu, -1, 0);
    ConfigLogger::log_limit("bitenc_decode_depth", bitenc, -1, 0);

    if ( full )
        ConfigLogger::log_flag("ignore_data", ignore_data);

    ConfigLogger::log_flag("decompress_pdf", decompress_pdf);
    ConfigLogger::log_flag("decompress_swf", decompress_swf);
    ConfigLogger::log_flag("decompress_zip", decompress_zip);
    ConfigLogger::log_flag("decompress_vba", decompress_vba);
    ConfigLogger::log_value("decompress_buffer_size", decompress_buffer_size);
}

