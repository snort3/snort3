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
/*
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  9.25.2012 - Initial Source Code. Hui Cao
 */

#include "file_enforcer.h"
#include "file_service.h"
#include "file_api.h"
#include "file_lib.h"

#include "framework/data_bus.h"
#include "hash/hashes.h"
#include "hash/sfxhash.h"
#include "main/snort_types.h"
#include "managers/action_manager.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "sfip/sfip_t.h"
#include "sfip/sf_ip.h"
#include "time/packet_time.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"

FileEnforcer::FileEnforcer()
{
    fileHash = sfxhash_new(MAX_FILES_TRACKED, sizeof(FileHashKey), sizeof(FileNode),
        MAX_MEMORY_USED, 1, NULL, NULL, 1);
    if (!fileHash)
        FatalError("Failed to create the expected channel hash table.\n");
}

FileEnforcer::~FileEnforcer()
{
    if (fileHash)
    {
        sfxhash_delete(fileHash);
    }
}

void FileEnforcer::update_file_node(FileNode* node, FileInfo* file)
{
    node->file = *file;
}

FileVerdict FileEnforcer::check_verdict(Flow* flow, FileNode* node, SFXHASH_NODE* hash_node)
{
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

    // Query the file policy in case verdict has been changed
    // Check file type first
    FilePolicy& inspect = FileService::get_inspect();

    verdict = inspect.type_lookup(flow, &(node->file));

    if ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE))
    {
        verdict = inspect.signature_lookup(flow, &(node->file));
    }

    if ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE))
    {
        verdict = node->file.verdict;
    }

    if (verdict == FILE_VERDICT_LOG)
    {
        sfxhash_free_node(fileHash, hash_node);
    }

    return verdict;
}

int FileEnforcer::store_verdict(Flow* flow, FileInfo* file)
{
    assert(file);
    size_t file_sig = file->get_file_id();

    if (!file_sig)
        return 0;

    time_t now = packet_time();
    FileHashKey hashKey;
    sfip_copy(hashKey.dip, &(flow->client_ip));
    sfip_copy(hashKey.sip, &(flow->server_ip));
    hashKey.file_sig = file_sig;

    FileNode* node;
    SFXHASH_NODE* hash_node = sfxhash_find_node(fileHash, &hashKey);
    if (hash_node)
    {
        if (!(node = (FileNode*)hash_node->data))
            sfxhash_free_node(fileHash, hash_node);
    }
    else
        node = nullptr;

    if (node)
    {
        node->expires = now + timeout;
        update_file_node(node, file);
    }
    else
    {
        FileNode new_node;
        DebugMessage(DEBUG_FILE, "Adding file node\n");

        update_file_node(&new_node, file);

        /*
         * use the time that we keep files around
         * since this info would effectively be invalid
         * after that anyway because the file that
         * caused this will be gone.
         */
        new_node.expires = now + timeout;

        /* Add it to the table */
        if (sfxhash_add(fileHash, &hashKey, &new_node) != SFXHASH_OK)
        {
            /* Uh, shouldn't get here...
             * There is already a node or couldn't alloc space
             * for key.  This means bigger problems, but fail
             * gracefully.
             */
            DebugMessage(DEBUG_FILE,
                "Failed to add file node to hash table\n");
            return -1;
        }
    }

    return 0;
}

bool FileEnforcer::apply_verdict(Flow* flow, FileInfo* file, FileVerdict verdict)
{
    file->verdict = verdict;

    if (verdict == FILE_VERDICT_BLOCK)
    {
        // can't block session inside a session
        Active::set_delayed_action(Active::ACT_BLOCK, 1);
        store_verdict(flow, file);
        return true;
    }
    else if (verdict == FILE_VERDICT_REJECT)
    {
        // can't reset session inside a session
        Active::set_delayed_action(Active::ACT_RESET, 1);
        store_verdict(flow, file);
        return true;
    }
    else if (verdict == FILE_VERDICT_PENDING)
    {
        /*Take the cached verdict*/
        Active::set_delayed_action(Active::ACT_DROP, 1);
        return true;
    }

    return false;
}

FileVerdict  FileEnforcer::cached_verdict_lookup(Flow* flow, FileInfo* file)
{
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;
    SFXHASH_NODE* hash_node;
    FileHashKey hashKey;
    FileNode* node;

    /* No hash table, or its empty?  Get out of dodge.  */
    if ((!fileHash) || (!sfxhash_count(fileHash)))
    {
        DebugMessage(DEBUG_FILE, "No expected sessions\n");
        return verdict;
    }

    assert(file);
    size_t file_sig = file->get_file_id();
    if (!file_sig)
        return verdict;

    sfip_copy(hashKey.dip, &(flow->client_ip));
    sfip_copy(hashKey.sip, &(flow->server_ip));
    hashKey.file_sig = file_sig;

    hash_node = sfxhash_find_node(fileHash, &hashKey);

    if (hash_node)
    {
        if (!(node = (FileNode*)hash_node->data))
            sfxhash_free_node(fileHash, hash_node);
    }
    else
        return verdict;

    if (node)
    {
        DebugMessage(DEBUG_FILE, "Found resumed file\n");
        if (node->expires && packet_time() > node->expires)
        {
            DebugMessage(DEBUG_FILE, "File expired\n");
            sfxhash_free_node(fileHash, hash_node);
            return verdict;
        }
        /*Query the file policy in case verdict has been changed*/
        verdict = check_verdict(flow, node, hash_node);
    }

    return verdict;
}

