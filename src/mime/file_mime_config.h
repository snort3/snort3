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

// file_mime_config.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_CONFIG_H
#define FILE_MIME_CONFIG_H

// List of MIME decode and log configuration functions
#include "main/snort_types.h"
#include "main/snort_config.h"

/*These are temporary values*/
#define DEFAULT_MIME_MEMCAP           838860
#define DEFAULT_DEPTH                 0
#define DEFAULT_DECOMP                100000
#define MAX_LOG_MEMCAP                104857600
#define MIN_LOG_MEMCAP                3276
#define MIN_MIME_MEM                  3276
#define MAX_DEPTH                     65536
#define MIN_DEPTH                     (-1)

namespace snort
{
class SO_PUBLIC DecodeConfig
{
public:
    void set_ignore_data(bool);
    bool is_ignore_data() const;

    void set_b64_depth(int);
    int get_b64_depth() const;

    void set_qp_depth(int);
    int get_qp_depth() const;

    void set_bitenc_depth(int);
    int get_bitenc_depth() const;

    void set_uu_depth(int);
    int get_uu_depth() const;

    void set_decompress_pdf(bool);
    bool is_decompress_pdf() const;

    void set_decompress_swf(bool);
    bool is_decompress_swf() const;

    void set_decompress_zip(bool);
    bool is_decompress_zip() const;

    void set_decompress_vba(bool);
    bool is_decompress_vba() const;

    void set_decompress_buffer_size(uint32_t);
    uint32_t get_decompress_buffer_size() const;

    int64_t get_file_depth() const;
    bool is_decoding_enabled() const;
    void sync_all_depths(const SnortConfig*);
    void show(bool = false) const;
    int get_max_depth(int) const;

private:
    bool ignore_data = false;
    int b64_depth  = DEFAULT_DEPTH;
    int qp_depth = DEFAULT_DEPTH;
    int bitenc_depth = DEFAULT_DEPTH;
    int uu_depth = DEFAULT_DEPTH;
    bool decompress_pdf = false;
    bool decompress_swf = false;
    bool decompress_zip = false;
    bool decompress_vba = false;
    uint32_t decompress_buffer_size = DEFAULT_DECOMP;
    int64_t file_depth = MIN_DEPTH;
    bool decode_enabled = true;
};
}
#endif

