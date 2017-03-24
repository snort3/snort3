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
//  file_cache.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_cache.h"

#include "hash/sfxhash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "time/packet_time.h"

#include "file_stats.h"

static int file_cache_free_func(void*, void* data)
{
    FileCache::FileNode* node = (FileCache::FileNode*)data;
    if (node)
    {
        delete node->file;
        node->file = nullptr;
    }
    return 0;
}

FileCache::FileCache()
{
    int max_files = snort_conf->file_config.max_files_cached;
    fileHash = sfxhash_new(max_files, sizeof(FileHashKey), sizeof(FileNode),
        0, 1, nullptr, file_cache_free_func, 1);
    if (!fileHash)
        FatalError("Failed to create the expected channel hash table.\n");
    sfxhash_set_max_nodes(fileHash, max_files);
}

FileCache::~FileCache()
{
    if (fileHash)
    {
        sfxhash_delete(fileHash);
    }
}

FileContext* FileCache::add(const FileHashKey& hashKey)
{
    FileNode new_node;
    /*
     * use the time that we keep files around
     * since this info would effectively be invalid
     * after that anyway because the file that
     * caused this will be gone.
     */
    time_t now = packet_time();
    new_node.expires = now + timeout;
    new_node.file = new FileContext;

    std::lock_guard<std::mutex> lock(cache_mutex);

    if (sfxhash_add(fileHash, (void*)&hashKey, &new_node) != SFXHASH_OK)
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

FileContext* FileCache::find(const FileHashKey& hashKey)
{
    std::lock_guard<std::mutex> lock(cache_mutex);

    // No hash table, or its empty?  Get out of dodge.
    if ((!fileHash) || (!sfxhash_count(fileHash)))
    {
        DebugMessage(DEBUG_FILE, "No expected sessions\n");
        return nullptr;
    }

    SFXHASH_NODE* hash_node = sfxhash_find_node(fileHash, &hashKey);

    if (!hash_node)
        return nullptr;

    FileNode* node = (FileNode*)hash_node->data;
    if (!node)
    {
        sfxhash_free_node(fileHash, hash_node);
        return nullptr;
    }

    DebugMessage(DEBUG_FILE, "Found resumed file\n");
    time_t now = packet_time();
    if (node->expires && now > node->expires)
    {
        DebugMessage(DEBUG_FILE, "File expired\n");
        sfxhash_free_node(fileHash, hash_node);
        return nullptr;
    }

    node->expires = now + timeout;
    return node->file;
}

