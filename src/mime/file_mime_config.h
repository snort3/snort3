//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// file_mime_config.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_CONFIG_H
#define FILE_MIME_CONFIG_H

// List of MIME decode and log configuration functions
#include "main/snort_types.h"

/*These are temporary values*/
#define DEFAULT_MAX_MIME_MEM          838860
#define DEFAULT_MIME_MEMCAP           838860
#define DEFAULT_DEPTH                 1464
#define MAX_LOG_MEMCAP                104857600
#define MIN_LOG_MEMCAP                3276
#define MAX_MIME_MEM                  104857600
#define MIN_MIME_MEM                  3276
#define MAX_DEPTH                     65535
#define MIN_DEPTH                     -1

class DecodeConfig
{
public:
    void set_ignore_data(bool);
    bool is_ignore_data();
    void set_max_mime_mem(int);
    int get_max_mime_mem();
    void set_b64_depth(int);
    int get_b64_depth();
    void set_qp_depth(int);
    int get_qp_depth();
    void set_bitenc_depth(int);
    int get_bitenc_depth();
    void set_uu_depth(int);
    int get_uu_depth();
    int get_max_depth();
    int64_t get_file_depth();
    bool is_decoding_enabled();
    void sync_all_depths();
    void print_decode_conf();

private:
    bool ignore_data = false;
    int max_mime_mem = DEFAULT_MAX_MIME_MEM;
    int b64_depth  = DEFAULT_DEPTH;
    int qp_depth = DEFAULT_DEPTH;
    int bitenc_depth = DEFAULT_DEPTH;
    int uu_depth = DEFAULT_DEPTH;
    int64_t file_depth = MIN_DEPTH;
    int max_depth = DEFAULT_DEPTH;  //is the max of all depths
    void set_file_depth(int64_t);
    void update_max_depth(int64_t);
};

#endif

