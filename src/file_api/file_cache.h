//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

namespace snort
{
struct XHash;
struct XHashNode;
}

class FileCache
{
public:

PADDING_GUARD_BEGIN
    struct FileHashKey
    {
        snort::SfIp sip;
        snort::SfIp dip;
        uint32_t padding;
        uint64_t file_id;
    };
PADDING_GUARD_END

    struct FileNode
    {
        time_t expires;
        snort::FileContext* file;
    };

    FileCache(int64_t max_files_cached);
    ~FileCache();

    void set_block_timeout(int64_t);
    void set_lookup_timeout(int64_t);
    void set_max_files(int64_t);

    snort::FileContext* get_file(snort::Flow*, uint64_t file_id, bool to_create);
    FileVerdict cached_verdict_lookup(snort::Flow*, snort::FileInfo*,
        snort::FilePolicyBase*);
    bool apply_verdict(snort::Flow*, snort::FileInfo*, FileVerdict, bool resume,
        snort::FilePolicyBase*);

private:
    snort::FileContext* add(const FileHashKey&, int64_t timeout);
    snort::FileContext* find(const FileHashKey&, int64_t);
    snort::FileContext* get_file(snort::Flow*, uint64_t file_id, bool to_create, int64_t timeout);
    FileVerdict check_verdict(snort::Flow*, snort::FileInfo*, snort::FilePolicyBase*);
    int store_verdict(snort::Flow*, snort::FileInfo*, int64_t timeout);

    /* The hash table of expected files */
    snort::XHash* fileHash = nullptr;
    int64_t block_timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
    int64_t lookup_timeout = DEFAULT_FILE_LOOKUP_TIMEOUT;
    int64_t max_files = DEFAULT_MAX_FILES_CACHED;
    std::mutex cache_mutex;
};

#endif

