//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "file_resume_block.h"

#include "file_service.h"
#include "file_api.h"

#include "main/snort_types.h"
#include "sfip/sfip_t.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "protocols/packet.h"
#include "packet_io/active.h"
#include "hash/sfxhash.h"
#include "hash/hashes.h"
#include "managers/action_manager.h"
#include "sfip/sf_ip.h"

/* The hash table of expected files */
static THREAD_LOCAL_TBD SFXHASH* fileHash = NULL;
Log_file_action_func log_file_action;
File_type_callback_func file_type_cb;
File_signature_callback_func file_signature_cb;

static FileState sig_file_state = { FILE_CAPTURE_SUCCESS, FILE_SIG_DONE };

typedef struct _FileHashKey
{
    sfip_t sip;
    sfip_t dip;
    uint32_t file_sig;
} FileHashKey;

typedef struct _FileNode
{
    time_t expires;
    File_Verdict verdict;
    uint32_t file_type_id;
    uint8_t sha256[SHA256_HASH_SIZE];
} FileNode;

#define MAX_FILES_TRACKED 16384

void file_resume_block_init(void)
{
    fileHash = sfxhash_new(MAX_FILES_TRACKED, sizeof(FileHashKey), sizeof(FileNode), 0, 1,
        NULL, NULL, 1);
    if (!fileHash)
        FatalError("Failed to create the expected channel hash table.\n");
}

void file_resume_block_cleanup(void)
{
    if (fileHash)
    {
        sfxhash_delete(fileHash);
        fileHash = NULL;
    }
}

static inline void updateFileNode(FileNode* node, File_Verdict verdict,
    uint32_t file_type_id, uint8_t* signature)
{
    node->verdict = verdict;
    node->file_type_id = file_type_id;
    if (signature)
    {
        memcpy(node->sha256, signature, SHA256_HASH_SIZE);
    }
}

/** *
 * @param sip - source IP address
 * @param dip - destination IP address
 * @param sport - server sport number
 * @param file_sig - file signature
 * @param expiry - session expiry in seconds.
 */
int file_resume_block_add_file(Packet* pkt, uint32_t file_sig, uint32_t timeout,
    File_Verdict verdict, uint32_t file_type_id, uint8_t* signature)
{
    FileHashKey hashKey;
    SFXHASH_NODE* hash_node = NULL;
    FileNode* node;
    FileNode new_node;
    const sfip_t* srcIP;
    const sfip_t* dstIP;
    Packet* p = (Packet*)pkt;
    time_t now = p->pkth->ts.tv_sec;

    srcIP = p->ptrs.ip_api.get_src();
    dstIP = p->ptrs.ip_api.get_dst();
    sfip_copy(hashKey.dip, dstIP);
    sfip_copy(hashKey.sip, srcIP);
    hashKey.file_sig = file_sig;

    hash_node = sfxhash_find_node(fileHash, &hashKey);
    if (hash_node)
    {
        if (!(node = (FileNode*)hash_node->data))
            sfxhash_free_node(fileHash, hash_node);
    }
    else
        node = NULL;
    if (node)
    {
        node->expires = now + timeout;
        updateFileNode(node, verdict, file_type_id, signature);
    }
    else
    {
        DebugMessage(DEBUG_FILE, "Adding file node\n");

        updateFileNode(&new_node, verdict, file_type_id, signature);

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

static inline File_Verdict checkVerdict(Packet* p, FileNode* node, SFXHASH_NODE* hash_node)
{
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;

    /*Query the file policy in case verdict has been changed
      Check file type first*/
    if (file_type_cb)
    {
        verdict = file_type_cb(p, p->flow, node->file_type_id, 0, DEFAULT_FILE_ID);
    }

    if ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE))
    {
        if (file_signature_cb)
        {
            verdict = file_signature_cb(p, p->flow, node->sha256, 0,
                &sig_file_state, 0, DEFAULT_FILE_ID);
        }
    }

    if ((verdict == FILE_VERDICT_UNKNOWN) ||
        (verdict == FILE_VERDICT_STOP_CAPTURE))
    {
        verdict = node->verdict;
    }

    if (verdict == FILE_VERDICT_LOG)
    {
        sfxhash_free_node(fileHash, hash_node);
        if (log_file_action)
        {
            log_file_action(p->flow, FILE_RESUME_LOG);
        }
    }
    else if (verdict == FILE_VERDICT_BLOCK)
    {
        Active::drop_packet(p, true);
        Active::block_session(p);

        if (log_file_action)
        {
            log_file_action(p->flow, FILE_RESUME_BLOCK);
        }
        node->verdict = verdict;
    }
    else if (verdict == FILE_VERDICT_REJECT)
    {
        Active::drop_packet(p, true);
        Active::reset_session(p);

        if (log_file_action)
        {
            log_file_action(p->flow, FILE_RESUME_BLOCK);
        }
        node->verdict = verdict;
    }
    else if (verdict == FILE_VERDICT_PENDING)
    {
        /*Take the cached verdict*/
        Active::drop_packet(p, true);

        if (FILE_VERDICT_REJECT == node->verdict)
            ActionManager::queue_reject(p);
        if (log_file_action)
        {
            log_file_action(p->flow, FILE_RESUME_BLOCK);
        }
        verdict = node->verdict;
    }

    return verdict;
}

File_Verdict file_resume_block_check(Packet* pkt, uint32_t file_sig)
{
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;
    const sfip_t* srcIP;
    const sfip_t* dstIP;
    SFXHASH_NODE* hash_node;
    FileHashKey hashKey;
    FileNode* node;
    Packet* p = (Packet*)pkt;

    /* No hash table, or its empty?  Get out of dodge.  */
    if ((!fileHash) || (!sfxhash_count(fileHash)))
    {
        DebugMessage(DEBUG_FILE, "No expected sessions\n");
        return verdict;
    }
    srcIP = p->ptrs.ip_api.get_src();
    dstIP = p->ptrs.ip_api.get_dst();
    sfip_copy(hashKey.dip, dstIP);
    sfip_copy(hashKey.sip, srcIP);
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
        if (node->expires && p->pkth->ts.tv_sec > node->expires)
        {
            DebugMessage(DEBUG_FILE, "File expired\n");
            sfxhash_free_node(fileHash, hash_node);
            return verdict;
        }
        /*Query the file policy in case verdict has been changed*/
        verdict = checkVerdict(p, node, hash_node);
    }
    return verdict;
}

