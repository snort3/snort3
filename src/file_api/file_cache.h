//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// file_cache.h author Hui Cao <huica@cisco.com>

#ifndef FILE_CACHE_H
#define FILE_CACHE_H

#include <mutex>

#include "file_api.h"
#include "file_lib.h"
#include "file_config.h"

#include "protocols/packet.h"
#include "hash/sfxhash.h"
#include "hash/hashes.h"

class FileCache
{
public:

    struct FileHashKey
    {
        sfip_t sip;
        sfip_t dip;
        uint64_t file_sig;
    };

    struct FileNode
    {
        time_t expires;
        FileContext* file;
    };

    FileCache();
    ~FileCache();
    FileContext* add(const FileHashKey&);
    FileContext* find(const FileHashKey&);

    static uint64_t num_add_fails;

private:

    /* The hash table of expected files */
    SFXHASH* fileHash = nullptr;
    uint32_t timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
    std::mutex cache_mutex;

};

#endif

