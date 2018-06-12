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
//  file_cache.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_cache.h"

#include "hash/xhash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "time/packet_time.h"

#include "file_flows.h"
#include "file_service.h"
#include "file_stats.h"

using namespace snort;

static int file_cache_anr_free_func(void*, void* data)
{
    FileCache::FileNode* node = (FileCache::FileNode*)data;

    if (!node)
        return 0;

    time_t now = packet_time();
    // only recycle expired nodes
    if (now > node->expires)
    {
        delete node->file;
        return 0;
    }
    else
        return 1;
}

static int file_cache_free_func(void*, void* data)
{
    FileCache::FileNode* node = (FileCache::FileNode*)data;
    if (node)
    {
        delete node->file;
    }
    return 0;
}

FileCache::FileCache(int64_t max_files_cached)
{
    max_files = max_files_cached;
    fileHash = xhash_new(max_files, sizeof(FileHashKey), sizeof(FileNode),
        0, 1, file_cache_anr_free_func, file_cache_free_func, 1);
    if (!fileHash)
        FatalError("Failed to create the expected channel hash table.\n");
    xhash_set_max_nodes(fileHash, max_files);
}

FileCache::~FileCache()
{
    if (fileHash)
    {
        xhash_delete(fileHash);
    }
}

void FileCache::set_block_timeout(int64_t timeout)
{
    std::lock_guard<std::mutex> lock(cache_mutex);
    block_timeout = timeout;
}

void FileCache::set_lookup_timeout(int64_t timeout)
{
    std::lock_guard<std::mutex> lock(cache_mutex);
    lookup_timeout = timeout;
}

void FileCache::set_max_files(int64_t max)
{
    std::lock_guard<std::mutex> lock(cache_mutex);

    int64_t minimal_files = ThreadConfig::get_instance_max() + 1;
    if (max < minimal_files)
    {
        max_files = minimal_files;
        ErrorMessage("Maximal number of files cached should be greater than "
            "number of threads\n");
    }
    else
        max_files = max;
    xhash_set_max_nodes(fileHash, max_files);
}

FileContext* FileCache::add(const FileHashKey& hashKey, int64_t timeout)
{
    FileNode new_node;
    /*
     * use the time that we keep files around
     * since this info would effectively be invalid
     * after that anyway because the file that
     * caused this will be gone.
     */
    time_t now = snort::packet_time();
    new_node.expires = now + timeout;
    new_node.file = new FileContext;

    std::lock_guard<std::mutex> lock(cache_mutex);

    if (xhash_add(fileHash, (void*)&hashKey, &new_node) != XHASH_OK)
    {
        /* Uh, shouldn't get here...
         * There is already a node or couldn't alloc space
         * for key.  This means bigger problems, but fail
         * gracefully.
         */
        file_counts.cache_add_fails++;
        delete new_node.file;
        return nullptr;
    }

    return new_node.file;
}

FileContext* FileCache::find(const FileHashKey& hashKey, int64_t timeout)
{
    std::lock_guard<std::mutex> lock(cache_mutex);

    if (!xhash_count(fileHash))
    {
        return nullptr;
    }

    XHashNode* hash_node = xhash_find_node(fileHash, &hashKey);

    if (!hash_node)
        return nullptr;

    FileNode* node = (FileNode*)hash_node->data;
    if (!node)
    {
        xhash_free_node(fileHash, hash_node);
        return nullptr;
    }

    time_t now = packet_time();
    if (node->expires && now > node->expires)
    {
        xhash_free_node(fileHash, hash_node);
        return nullptr;
    }

    if (node->expires <  now + timeout)
        node->expires = now + timeout;
    return node->file;
}

FileContext* FileCache::get_file(Flow* flow, uint64_t file_id, bool to_create,
    int64_t timeout)
{
    FileHashKey hashKey;
    hashKey.dip.set(flow->client_ip);
    hashKey.sip.set(flow->server_ip);
    hashKey.padding = 0;
    hashKey.file_id = file_id;
    FileContext* file = find(hashKey, timeout);
    if (to_create and !file)
       file = add(hashKey, timeout);

    return file;
}

FileContext* FileCache::get_file(Flow* flow, uint64_t file_id, bool to_create)
{
    return get_file(flow, file_id, to_create, lookup_timeout);
}

FileVerdict FileCache::check_verdict(Flow* flow, FileInfo* file,
    FilePolicyBase* policy)
{
    assert(file);

    FileVerdict verdict = policy->type_lookup(flow, file);

    if ( file->get_file_sig_sha256() and
        ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE)))
    {
        verdict = policy->signature_lookup(flow, file);
    }

    if ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE))
    {
        verdict = file->verdict;
    }

    return verdict;
}

int FileCache::store_verdict(Flow* flow, FileInfo* file, int64_t timeout)
{
    assert(file);
    uint64_t file_id = file->get_file_id();

    if (!file_id)
        return 0;

    FileContext* file_got = get_file(flow, file_id, true, timeout);
    if (file_got)
        *((FileInfo*)(file_got)) = *file;
    else
        return -1;
    return 0;
}

bool FileCache::apply_verdict(Flow* flow, FileInfo* file, FileVerdict verdict,
    bool resume, FilePolicyBase* policy)
{
    file->verdict = verdict;

    switch (verdict)
    {

    case FILE_VERDICT_UNKNOWN:
        return false;
    case FILE_VERDICT_LOG:
        if (resume)
            policy->log_file_action(flow, file, FILE_RESUME_LOG);
        return false;
    case FILE_VERDICT_BLOCK:
         // can't block session inside a session
         Active::set_delayed_action(Active::ACT_BLOCK, true);
         break;

    case FILE_VERDICT_REJECT:
        // can't reset session inside a session
        Active::set_delayed_action(Active::ACT_RESET, true);
        break;
    case FILE_VERDICT_PENDING:
        Active::set_delayed_action(Active::ACT_DROP, true);
        if (resume)
            policy->log_file_action(flow, file, FILE_RESUME_BLOCK);
        else
        {
            store_verdict(flow, file, lookup_timeout);
            FileFlows* files = FileFlows::get_file_flows(flow);
            if (files)
                files->add_pending_file(file->get_file_id());
        }
        return true;
    default:
        return false;
    }

    if (resume)
        policy->log_file_action(flow, file, FILE_RESUME_BLOCK);
    else
        store_verdict(flow, file, block_timeout);
    return true;

}

FileVerdict FileCache::cached_verdict_lookup(Flow* flow, FileInfo* file,
    FilePolicyBase* policy)
{
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

    assert(file);
    uint64_t file_id = file->get_file_id();
    if (!file_id)
        return verdict;

    FileContext* file_found = get_file(flow, file_id, false);

    if (file_found)
    {
        /*Query the file policy in case verdict has been changed*/
        verdict = check_verdict(flow, file_found, policy);
        apply_verdict(flow, file_found, verdict, true, policy);
    }

    return verdict;
}

