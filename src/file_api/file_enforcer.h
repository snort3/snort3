//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// file_enforcer.h author Hui Cao <huica@cisco.com>

#ifndef FILE_ENFORCER_H
#define FILE_ENFORCER_H

// If a file transferred through HTTP is blocked, a new session might be created
// to request the file data left. To block the new session, we use URL and IPs
// to continue blocking the same file.

#include "hash/xhash.h"
#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"

#include "file_config.h"
#include "file_policy.h"

namespace snort
{
class FileInfo;
class FilePolicyBase;
class Flow;
}

#define MAX_FILES_TRACKED 16384
#define MAX_MEMORY_USED (10*1024*1024)  // 10M

class FileEnforcer
{
public:
    struct FileNode
    {
        time_t expires;
        snort::FileInfo* file;
    };

    FileEnforcer();
    ~FileEnforcer();
    FileVerdict cached_verdict_lookup(snort::Flow*, snort::FileInfo*, snort::FilePolicyBase*);
    bool apply_verdict(snort::Flow*, snort::FileInfo*, FileVerdict, bool resume, snort::FilePolicyBase*);

private:
// FIXIT-L Merge definition with duplicate in file_cache.h?
PADDING_GUARD_BEGIN
    struct FileHashKey
    {
        snort::SfIp sip;
        snort::SfIp dip;
        uint32_t padding;
        uint64_t file_sig;
    };
PADDING_GUARD_END

    void update_file_node(FileNode*, snort::FileInfo*);
    FileVerdict check_verdict(snort::Flow*, FileNode*, XHashNode*, snort::FilePolicyBase*);
    int store_verdict(snort::Flow*, snort::FileInfo*);

    /* The hash table of expected files */
    XHash* fileHash = nullptr;
    uint32_t timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
};

#endif

