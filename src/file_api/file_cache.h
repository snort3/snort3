//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"

#include "file_config.h"

struct SFXHASH;

class FileCache
{
public:
// FIXIT-L Merge definition with duplicate in file_enforcer.h?
PADDING_GUARD_BEGIN
    struct FileHashKey
    {
        SfIp sip;
        SfIp dip;
        uint32_t padding;
        uint64_t file_sig;
    };
PADDING_GUARD_END

    struct FileNode
    {
        time_t expires;
        FileContext* file;
    };

    FileCache();
    ~FileCache();
    FileContext* add(const FileHashKey&);
    FileContext* find(const FileHashKey&);

private:
    /* The hash table of expected files */
    SFXHASH* fileHash = nullptr;
    uint32_t timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
    std::mutex cache_mutex;
};

#endif

