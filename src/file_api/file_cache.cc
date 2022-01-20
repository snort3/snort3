//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow_key.h"
#include "hash/hash_defs.h"
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

class ExpectedFileCache : public XHash
{
public:
    ExpectedFileCache(unsigned rows, unsigned key_len, unsigned datasize)
        : XHash(rows, key_len, datasize, 0)
    { }

    ~ExpectedFileCache() override
    {
        delete_hash_table();
    }

    bool is_node_recovery_ok(HashNode* hnode) override
    {
        FileCache::FileNode* node = (FileCache::FileNode*)hnode->data;
        if ( !node )
            return true;

        struct timeval now;
        packet_gettimeofday(&now);
        if ( timercmp(&node->cache_expire_time, &now, <) )
           return true;
        else
            return false;
    }

    void free_user_data(HashNode* hnode) override
    {
        FileCache::FileNode* node = (FileCache::FileNode*)hnode->data;
        if ( node )
            delete node->file;
    }
};

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
    fileHash = new ExpectedFileCache(max_files, sizeof(FileHashKey), sizeof(FileNode));
    fileHash->set_max_nodes(max_files);
}

FileCache::~FileCache()
{
    delete fileHash;
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
    fileHash->set_max_nodes(max_files);
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

    struct timeval time_to_add = { static_cast<time_t>(timeout), 0 };
    timeradd(&now, &time_to_add, &new_node.cache_expire_time);

    new_node.file = new FileContext;

    std::lock_guard<std::mutex> lock(cache_mutex);

    if (fileHash->insert((void*)&hashKey, &new_node) != HASH_OK)
    {
        /* Uh, shouldn't get here...
         * There is already a node or couldn't alloc space
         * for key.  This means bigger problems, but fail
         * gracefully.
         */
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
            "add:Insert failed in file cache, returning\n"); 
        file_counts.cache_add_fails++;
        delete new_node.file;
        return nullptr;
    }

    return new_node.file;
}

FileContext* FileCache::find(const FileHashKey& hashKey, int64_t timeout)
{
    std::lock_guard<std::mutex> lock(cache_mutex);

    if ( !fileHash->get_num_nodes() )
        return nullptr;

    HashNode* hash_node = fileHash->find_node(&hashKey);
    if ( !hash_node )
        return nullptr;

    FileNode* node = (FileNode*)hash_node->data;
    if ( !node )
    {
        fileHash->release_node(hash_node);
        return nullptr;
    }

    struct timeval now;
    packet_gettimeofday(&now);

    if ( timercmp(&node->cache_expire_time, &now, <) )
    {
        fileHash->release_node(hash_node);
        return nullptr;
    }

    struct timeval next_expire_time;
    struct timeval time_to_add = { static_cast<time_t>(timeout), 0 };
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
    hashKey.dgroup = flow->client_group;
    hashKey.sgroup = flow->server_group;
    hashKey.file_id = file_id;
    hashKey.asid = flow->key->addressSpaceId;
    hashKey.padding[0] = hashKey.padding[1] = hashKey.padding[2] = 0;
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
    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "check_verdict:verdict after type lookup %d\n", verdict);

    if (verdict == FILE_VERDICT_STOP_CAPTURE)
    {
        verdict = FILE_VERDICT_UNKNOWN;
    }

    if ( file->get_file_sig_sha256() and verdict == FILE_VERDICT_UNKNOWN )
    {
        verdict = policy->signature_lookup(p, file);
    }

    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "check_verdict:verdict being returned %d\n", verdict);
    return verdict;
}

int FileCache::store_verdict(Flow* flow, FileInfo* file, int64_t timeout)
{
    assert(file);
    uint64_t file_id = file->get_file_id();

    if (!file_id)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, GET_CURRENT_PACKET,
            "store_verdict: file context doesn't have file id\n");
        return 0;
    }

    FileContext* file_got = get_file(flow, file_id, true, timeout);
    if (file_got)
    {
        *((FileInfo*)(file_got)) = *file;

        if (FILE_VERDICT_PENDING == file->verdict and file != file_got)
        {
            if (file->get_file_data() and !file_got->get_file_data())
            {
                file_got->set_file_data(file->get_file_data());
                file->set_file_data(nullptr);
            }
        }
        else
        {
            if (file->get_file_data() and file != file_got)
            {
                file_got->set_file_data(nullptr);
            }
        }
    }
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
    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
        "apply_verdict %d\n", verdict);

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
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:FILE_VERDICT_BLOCK with action block\n");
        act->set_delayed_action(Active::ACT_BLOCK, true);
        act->set_drop_reason("file");
        break;

    case FILE_VERDICT_REJECT:
        // can't reset session inside a session
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:FILE_VERDICT_REJECT with action reset\n");
        act->set_delayed_action(Active::ACT_RESET, true);
        act->set_drop_reason("file");
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
            FileConfig* fc = get_file_config(p->context->conf);

            //  Block session on timeout if configured, otherwise use the
            //  current action.
            if (fc->block_timeout_lookup)
            {
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                    "apply_verdict:FILE_VERDICT_PENDING with action reset\n");
                act->set_delayed_action(Active::ACT_RESET, true);
            }

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
            else
                file_ctx->verdict = FILE_VERDICT_LOG;

            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                "File signature lookup: timed out after %" PRIi64 "ms.\n",
                time_elapsed_ms(&now, &file_ctx->pending_expire_time, lookup_timeout));

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
                add_time = { static_cast<time_t>(lookup_timeout), 0 };
                timeradd(&now, &add_time, &file_ctx->pending_expire_time);

                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                    "File signature lookup: adding new packet to retry queue.\n");

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

                    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                        "File signature lookup adding packet to retry queue"
                        "Resume=%d, Waited %" PRIi64 "ms.\n", resume,	
                        time_elapsed_ms(&now, &file_ctx->pending_expire_time, lookup_timeout));
                }
            }

            act->set_delayed_action(Active::ACT_RETRY, true);
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                "apply_verdict:FILE_VERDICT_PENDING with action retry\n");

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
            else if (store_verdict(flow, file_ctx, lookup_timeout) != 0)
            {
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                    "apply_verdict:FILE_VERDICT_PENDING with action drop\n");
                act->set_delayed_action(Active::ACT_DROP, true);
            }
            else
            {
                FileFlows* files = FileFlows::get_file_flows(flow);
                if (files)
                {
                    files->add_pending_file(file_ctx->get_file_id());
                    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                        "apply_verdict:Adding file id to pending\n");
                }
            }
        }
        return true;
    default:
        return false;
    }

    if (resume)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:Resume block file\n");
        file_ctx->log_file_event(flow, policy);
        policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
    }
    else if (file_ctx->is_cacheable())
    {
        store_verdict(flow, file_ctx, block_timeout);
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:storing the file verdict\n");
    }

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
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
            "cached_verdict_lookup:File id not found, returning\n");
        return verdict;
    }

    FileContext* file_found = get_file(flow, file_id, false);

    if (file_found)
    {
        /*Query the file policy in case verdict has been changed*/
        verdict = check_verdict(p, file_found, policy);
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "cached_verdict_lookup:Verdict received from cached_verdict_lookup %d\n", verdict);
        apply_verdict(p, file_found, verdict, true, policy);
        // Update the current file context from cached context
        *file = *(FileInfo*)file_found;
    }

    return verdict;
}

