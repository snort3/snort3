//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "packet_tracer/packet_tracer.h"
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

    struct timeval now;
    packet_gettimeofday(&now);

    // only recycle expired nodes
    if (timercmp(&node->cache_expire_time, &now, <))
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

// Return the time in ms since we started waiting for pending file lookup.
static int64_t time_elapsed_ms(struct timeval* now, struct timeval* expire_time, int64_t lookup_timeout)
{
    if(!now or !now->tv_sec or !expire_time or !expire_time->tv_sec)
        return 0;

    return lookup_timeout * 1000 + timersub_ms(now, expire_time);
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
    struct timeval now;
    packet_gettimeofday(&now);

    struct timeval time_to_add = { timeout, 0 };
    timeradd(&now, &time_to_add, &new_node.cache_expire_time);

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

    struct timeval now;
    packet_gettimeofday(&now);

    if (timercmp(&node->cache_expire_time, &now, <))
    {
        xhash_free_node(fileHash, hash_node);
        return nullptr;
    }

    struct timeval next_expire_time;
    struct timeval time_to_add = { timeout, 0 };
    timeradd(&now, &time_to_add, &next_expire_time);

    //  Refresh the timer on the cache.
    if (timercmp(&node->cache_expire_time, &next_expire_time, <))
        node->cache_expire_time = next_expire_time;

    return node->file;
}

FileContext* FileCache::get_file(Flow* flow, uint64_t file_id, bool to_create,
    int64_t timeout)
{
    FileHashKey hashKey;
    hashKey.dip = flow->client_ip;
    hashKey.sip = flow->server_ip;
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

FileVerdict FileCache::check_verdict(Packet* p, FileInfo* file,
    FilePolicyBase* policy)
{
    assert(file);

    FileVerdict verdict = policy->type_lookup(p, file);

    if ( file->get_file_sig_sha256() and
        ((verdict == FILE_VERDICT_UNKNOWN) or (verdict == FILE_VERDICT_STOP_CAPTURE)))
    {
        verdict = policy->signature_lookup(p, file);
    }

    if ((verdict == FILE_VERDICT_UNKNOWN) or (verdict == FILE_VERDICT_STOP_CAPTURE))
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

bool FileCache::apply_verdict(Packet* p, FileContext* file_ctx, FileVerdict verdict,
    bool resume, FilePolicyBase* policy)
{
    Flow* flow = p->flow;
    Active* act = p->active;
    struct timeval now = {0, 0};
    struct timeval add_time;

    if (verdict != FILE_VERDICT_PENDING)
        timerclear(&file_ctx->pending_expire_time);

    file_ctx->verdict = verdict;
    switch (verdict)
    {

    case FILE_VERDICT_UNKNOWN:
        return false;
    case FILE_VERDICT_LOG:
        if (resume)
            policy->log_file_action(flow, file_ctx, FILE_RESUME_LOG);
        return false;
    case FILE_VERDICT_BLOCK:
         // can't block session inside a session
         act->set_delayed_action(Active::ACT_BLOCK, true);
         break;

    case FILE_VERDICT_REJECT:
        // can't reset session inside a session
        act->set_delayed_action(Active::ACT_RESET, true);
        break;
    case FILE_VERDICT_STOP_CAPTURE:
        file_ctx->stop_file_capture();
        return false;
    case FILE_VERDICT_PENDING:
        packet_gettimeofday(&now);

        if (timerisset(&file_ctx->pending_expire_time) and
            timercmp(&file_ctx->pending_expire_time, &now, <))
        {
            //  Timed out while waiting for pending verdict.
            FileConfig* fc = get_file_config(SnortConfig::get_conf());

            //  Block session on timeout if configured, otherwise use the
            //  current action.
            if (fc->block_timeout_lookup)
                act->set_delayed_action(Active::ACT_RESET, true);

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);

            if (PacketTracer::is_active())
            {
                PacketTracer::log("File signature lookup: timed out after %" PRIi64 "ms.\n", time_elapsed_ms(&now, &file_ctx->pending_expire_time, lookup_timeout));
            }
        }
        else
        {
            //  Add packet to retry queue while we wait for response.

            if (!timerisset(&file_ctx->pending_expire_time))
            {
                add_time = { lookup_timeout, 0 };
                timeradd(&now, &add_time, &file_ctx->pending_expire_time);

                if (PacketTracer::is_active())
                    PacketTracer::log("File signature lookup: adding new packet to retry queue.\n");
            }
            else if (PacketTracer::is_active())
            {
                //  Won't add packet to retry queue if it is a retransmit
                //  and not from the retry queue since it should already
                //  be there.
                if (!(p->packet_flags & PKT_RETRANSMIT) or p->is_retry())
                {
                    PacketTracer::log("File signature lookup: adding packet to retry queue. Resume=%d, Waited %" PRIi64 "ms.\n", resume, time_elapsed_ms(&now, &file_ctx->pending_expire_time, lookup_timeout));
                }
            }

            act->set_delayed_action(Active::ACT_RETRY, true);

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
            else if (store_verdict(flow, file_ctx, lookup_timeout) != 0)
                act->set_delayed_action(Active::ACT_DROP, true);
            else
            {
                FileFlows* files = FileFlows::get_file_flows(flow);
                if (files)
                    files->add_pending_file(file_ctx->get_file_id());
            }
        }
        return true;
    default:
        return false;
    }

    if (resume)
    {
        file_ctx->log_file_event(flow, policy);
        policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
    }
    else
        store_verdict(flow, file_ctx, block_timeout);

    return true;
}

FileVerdict FileCache::cached_verdict_lookup(Packet* p, FileInfo* file,
    FilePolicyBase* policy)
{
    Flow* flow = p->flow;
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

    assert(file);
    uint64_t file_id = file->get_file_id();
    if (!file_id)
        return verdict;

    FileContext* file_found = get_file(flow, file_id, false);

    if (file_found)
    {
        /*Query the file policy in case verdict has been changed*/
        verdict = check_verdict(p, file_found, policy);
        apply_verdict(p, file_found, verdict, true, policy);
        // Update the current file context from cached context
        *file = *(FileInfo*)file_found;
    }

    return verdict;
}

