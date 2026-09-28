//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <cinttypes>
#include <cstring>

#include <limits>
#include <vector>

#include "control/control.h"
#include "flow/flow_key.h"
#include "hash/hash_defs.h"
#include "hash/hashes.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "pub_sub/file_events.h"
#include "time/packet_time.h"

#include "file_flows.h"
#include "file_inspect.h"
#include "file_module.h"
#include "file_service.h"
#include "file_stats.h"

#define DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM 3600    // 1 hour

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

        if ( node->file and node->file->is_in_use() )
            return false;

        struct timeval now;
        packet_gettimeofday(&now);
        // cppcheck-suppress syntaxError ; timercmp's comparison operator is a macro argument
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

namespace
{
struct CacheNodePin
{
    CacheNodePin(std::mutex& m, FileContext* f) : cache_mutex(m), file(f) { }
    ~CacheNodePin()
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        file->unpin();
    }
    std::mutex& cache_mutex;
    FileContext* file;
};
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
    fileHash = new ExpectedFileCache(max_files, sizeof(FileHashKey), sizeof(FileNode));
    fileHash->set_max_nodes(max_files);
}

FileCache::~FileCache()
{
    delete fileHash;
}

void FileCache::set_block_timeout(int64_t timeout)
{
    block_timeout.store(timeout, std::memory_order_relaxed);
}

void FileCache::set_lookup_timeout(int64_t timeout)
{
    lookup_timeout.store(timeout, std::memory_order_relaxed);
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

int64_t FileCache::get_num_entries()
{
    std::lock_guard<std::mutex> lock(cache_mutex);
    return fileHash ? fileHash->get_num_nodes() : 0;
}

FileContext* FileCache::find_add(const FileHashKey& hashKey, int64_t timeout)
{
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
        if ( !node->file or !node->file->is_in_use() )
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

FileContext* FileCache::add(const FileHashKey& hashKey, int64_t timeout, bool &cache_full, int64_t& cache_expire, bool cache_sync)
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

    std::lock_guard<std::mutex> lock(cache_mutex);
    FileContext* file = find_add(hashKey, timeout);

    if (!file)
    {
        new_node.file = new FileContext;
        int ret = fileHash->insert((void*)&hashKey, &new_node);
        cache_expire = new_node.cache_expire_time.tv_sec;

        if (ret != HASH_OK)
        {
            /* There is already a node or couldn't alloc space for key or cache is full.
             * We would retry the packet in case of HASH_NOMEM and fail gracefully in other cases.
             */
            if (ret == HASH_NOMEM)
            {
                if (PacketTracer::is_active())
                    PacketTracer::log("add:Insert failed in file cache, returning\n");
                cache_full = true;
                file_counts.file_cache_full++;
            }
            else
            {
                file_counts.file_cache_failures++;
            }

            if (!cache_sync)
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                    "add:Insert failed in file cache, returning\n");
            file_counts.cache_add_fails++;
            delete new_node.file;
            return nullptr;
        }

        file_counts.file_cache_total_entries++;
        int64_t num_entries = fileHash->get_num_nodes();
        if (num_entries > (int64_t)file_counts.file_cache_max_entries)
            file_counts.file_cache_max_entries = num_entries;
        return new_node.file;
    }
    else
    {
        if (!cache_sync)
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                "add:file already found in file cache, returning\n");
        return file;
    }
}

FileContext* FileCache::find(const FileHashKey& hashKey, int64_t timeout, int64_t& cache_expire)
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
        if ( !node->file or !node->file->is_in_use() )
            fileHash->release_node(hash_node);
        return nullptr;
    }

    struct timeval next_expire_time;
    struct timeval time_to_add = { static_cast<time_t>(timeout), 0 };
    timeradd(&now, &time_to_add, &next_expire_time);

    //  Refresh the timer on the cache.
    if (timercmp(&node->cache_expire_time, &next_expire_time, <))
        node->cache_expire_time = next_expire_time;

    cache_expire = node->cache_expire_time.tv_sec;
    return node->file;
}

FileContext* FileCache::get_file(Flow* flow, uint64_t file_id, bool to_create,
    int64_t timeout, bool using_cache_entry, bool &cache_full, int64_t& cache_expire)
{
    FileHashKey hashKey;
    make_key(flow, file_id, hashKey);

    FileContext* file = nullptr;
    if (using_cache_entry)
        file = find(hashKey, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM, cache_expire);
    else
        file = find(hashKey, timeout, cache_expire);

    if (to_create and !file)
        file = add(hashKey, timeout, cache_full, cache_expire);

    if (file and !file->get_config() and !file->get_inspector())
    {
        FileInspect *inspector = (FileInspect*)InspectorManager::acquire_file_inspector();
        if (inspector)
        {
            FileConfig *fc = inspector->config;
            file->set_config(fc);
            file->set_inspector(inspector);
        }
    }
    return file;
}

FileContext* FileCache::get_file(Flow* flow, uint64_t file_id, bool to_create, bool using_cache_entry)
{
    bool cache_full = false;
    int64_t cache_expire = 0;
    return get_file(flow, file_id, to_create, lookup_timeout.load(std::memory_order_relaxed),
        using_cache_entry, cache_full, cache_expire);
}

FileContext* FileCache::find_and_pin(Flow* flow, uint64_t file_id, int64_t timeout)
{
    FileHashKey hashKey;
    make_key(flow, file_id, hashKey);

    FileContext* file = nullptr;
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        file = find_add(hashKey, timeout);
        if (file)
            file->pin();
    }

    if (file and !file->get_config() and !file->get_inspector())
    {
        FileInspect* inspector = (FileInspect*)InspectorManager::acquire_file_inspector();
        if (inspector)
        {
            file->set_config(inspector->config);
            file->set_inspector(inspector);
        }
    }
    return file;
}

void FileCache::make_key(Flow* flow, uint64_t file_id, FileHashKey& hashKey) const
{
    hashKey = {};
    hashKey.dip = flow->client_ip;
    hashKey.sip = flow->server_ip;
    hashKey.dgroup = flow->client_group;
    hashKey.sgroup = flow->server_group;
    hashKey.file_id = file_id;
    hashKey.asid = flow->key->addressSpaceId;
}

FileContext* FileCache::dup_cache_context(Flow* flow, uint64_t file_id, bool& is_pending)
{
    FileContext* copy = new FileContext();
    is_pending = false;

    FileHashKey hashKey;
    make_key(flow, file_id, hashKey);
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        FileContext* cached = find_add(hashKey, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM);
        if (cached)
        {
            std::lock_guard<std::recursive_mutex> udlock(cached->user_file_data_mutex);
            is_pending = (cached->verdict == FILE_VERDICT_PENDING);
            copy->copy(*cached, false);
            if (!is_pending and !cached->is_cacheable())
                copy->set_not_cacheable();
            return copy;
        }
    }
    delete copy;
    return nullptr;
}

bool FileCache::verdict_publish_blocked(FileVerdict cached, FileVerdict incoming)
{
    const bool cached_terminal = (cached != FILE_VERDICT_UNKNOWN and cached != FILE_VERDICT_PENDING);
    const bool incoming_nonterminal = (incoming == FILE_VERDICT_UNKNOWN or incoming == FILE_VERDICT_PENDING);
    return cached_terminal and incoming_nonterminal;
}

void FileCache::publish_flow_verdict_locked(const FileHashKey& key, int64_t timeout, FileInfo* src,
    bool is_cacheable)
{
    std::lock_guard<std::mutex> lock(cache_mutex);
    FileContext* node = find_add(key, timeout);
    if (!node)
        return;

    const bool same = (src == static_cast<FileInfo*>(node));

    std::lock_guard<std::recursive_mutex> udlock(node->user_file_data_mutex);

    const uint8_t* node_sha = node->get_file_sig_sha256();
    const uint8_t* src_sha = src->get_file_sig_sha256();
    const bool cross_file = node_sha and src_sha and
        memcmp(node_sha, src_sha, SHA256_HASH_SIZE) != 0;

    if (verdict_publish_blocked(node->verdict, src->verdict) and !cross_file)
    {
        if (FILE_VERDICT_PENDING == src->verdict and !same)
        {
            if (src->get_file_data() and !node->get_file_data())
            {
                node->set_file_data(src->get_file_data());
                src->set_file_data(nullptr);
            }
            if (timerisset(&src->pending_expire_time) and
                !timerisset(&node->pending_expire_time))
                node->pending_expire_time = src->pending_expire_time;
        }
        return;
    }

    *((FileInfo*)node) = *src;

    if (!same and not is_cacheable)
        node->set_not_cacheable();

    if (FILE_VERDICT_PENDING == src->verdict and !same)
    {
        if (src->get_file_data() and !node->get_file_data())
        {
            node->set_file_data(src->get_file_data());
            src->set_file_data(nullptr);
        }
    }
    else if (!same and src->get_file_data())
    {
        node->set_file_data(nullptr);
    }
}

void FileCache::take_pending_file_data(Flow* flow, uint64_t file_id, FileInfo* dst)
{
    FileHashKey hashKey;
    make_key(flow, file_id, hashKey);

    std::lock_guard<std::mutex> lock(cache_mutex);
    FileContext* node = find_add(hashKey, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM);
    if (node and node->verdict == FILE_VERDICT_PENDING and node->get_file_data() and !dst->get_file_data())
    {
        std::lock_guard<std::recursive_mutex> udlock(node->user_file_data_mutex);
        dst->set_file_data(node->get_file_data());
        node->set_file_data(nullptr);
    }
}

bool FileCache::cached_context_not_cacheable(Flow* flow, uint64_t file_id)
{
    FileHashKey hashKey;
    make_key(flow, file_id, hashKey);

    std::lock_guard<std::mutex> lock(cache_mutex);
    FileContext* node = find_add(hashKey, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM);
    return node and !node->is_cacheable();
}

void FileCache::store_shared_verdict(const FileHashKey& key, int64_t timeout, FileInfo& src)
{
    bool cache_full = false;
    int64_t cache_expire = 0;
    add(key, timeout, cache_full, cache_expire, true);

    std::lock_guard<std::mutex> lock(cache_mutex);
    FileContext* node = find_add(key, timeout);
    if (!node)
        return;

    const bool cached_condemned =
        (node->verdict == FILE_VERDICT_BLOCK or node->verdict == FILE_VERDICT_REJECT);
    const bool incoming_condemned =
        (src.verdict == FILE_VERDICT_BLOCK or src.verdict == FILE_VERDICT_REJECT);
    if (verdict_publish_blocked(node->verdict, src.verdict) or (cached_condemned and !incoming_condemned))
        return;

    std::lock_guard<std::recursive_mutex> udlock(node->user_file_data_mutex);
    *((FileInfo*)node) = src;
}

FileVerdict FileCache::check_verdict(Packet* p, FileInfo* file,
    FilePolicyBase* policy, const uint8_t* current_data, uint32_t current_data_len)
{
    assert(file);

    FileVerdict verdict;
    {
        std::lock_guard<std::recursive_mutex> udlock(file->user_file_data_mutex);
        verdict = policy->type_lookup(p, file);
    }

    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "check_verdict:verdict after type lookup %d\n", verdict);

    if (verdict == FILE_VERDICT_STOP_CAPTURE)
    {
        verdict = FILE_VERDICT_UNKNOWN;
    }

    if ( file->get_file_sig_sha256() and verdict <= FILE_VERDICT_LOG )
    {
        std::lock_guard<std::recursive_mutex> udlock(file->user_file_data_mutex);
        file->set_capture_file_data(current_data, current_data_len);
        verdict = policy->signature_lookup(p, file);
    }

    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "check_verdict:verdict being returned %d\n", verdict);
    return verdict;
}

void FileCache::publish_file_cache_event(Flow* flow, FileInfo* file, int64_t timeout)
{
    if (SnortConfig::get_conf()->mp_dbus)
    {	    
        FileHashKey hashkey;
        make_key(flow, file->get_file_id(), hashkey);


        std::shared_ptr<FileMPEvent> fe = std::make_shared<FileMPEvent>(hashkey, timeout, *file);
        unsigned file_pub_id = MPDataBus::get_id(file_mp_pub_key);
        MPDataBus::publish(file_pub_id, FileMPEvents::FILE_SHARE_SYNC, fe);

        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "File Cache Sharing: Publish event with file_id %" PRIu64 "\n", hashkey.file_id);
    }
}

int FileCache::store_verdict(Flow* flow, FileInfo* file, int64_t timeout, bool &cache_full, bool is_cacheable)
{
    assert(file);
    uint64_t file_id = file->get_file_id();
    int64_t cache_expire = 0;

    if (!file_id)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, GET_CURRENT_PACKET,
            "store_verdict: file context doesn't have file id\n");
        return 0;
    }

    FileContext* file_got = get_file(flow, file_id, true, timeout, false, cache_full, cache_expire);
    if (!file_got)
        return -1;

    publish_file_cache_event(flow, file, cache_expire);

    FileHashKey key;
    make_key(flow, file_id, key);
    publish_flow_verdict_locked(key, timeout, file, is_cacheable);
    return 0;
}

bool FileCache::apply_verdict(Packet* p, FileContext* file_ctx, FileVerdict verdict,
    bool resume, FilePolicyBase* policy)
{
    Flow* flow = p->flow;
    Active* act = p->active;
    struct timeval now = {0, 0};
    struct timeval add_time;
    bool cache_full = false;

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
        {
            file_ctx->log_file_event(flow, policy);
            policy->log_file_action(flow, file_ctx, FILE_RESUME_LOG);
        }
        return false;
    case FILE_VERDICT_BLOCK:
        // can't block session inside a session
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:FILE_VERDICT_BLOCK with action block\n");

        if (PacketTracer::is_active())
        {
            PacketTracer::log("File: FILE_VERDICT_BLOCK with action block\n");
        }

        act->set_delayed_action(Active::ACT_BLOCK, true);
        act->set_drop_reason("file");
        break;

    case FILE_VERDICT_REJECT:
        // can't reset session inside a session
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:FILE_VERDICT_REJECT with action reset\n");

        if (PacketTracer::is_active())
        {
            PacketTracer::log("File: FILE_VERDICT_REJECT with action reset\n");
        }

        act->set_delayed_action(Active::ACT_RESET, true);
        act->set_drop_reason("file");
        break;
    case FILE_VERDICT_STOP_CAPTURE:
        file_ctx->stop_file_capture();
        return false;
    case FILE_VERDICT_PENDING:
    {
        int64_t cur_lookup_timeout = lookup_timeout.load(std::memory_order_relaxed);
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

                if (PacketTracer::is_active())
                {
                    PacketTracer::log("File: FILE_VERDICT_PENDING with action reset due to timeout\n");
                }

                act->set_delayed_action(Active::ACT_RESET, true);
            }

            file_ctx->set_timedout();
            file_counts.file_lookup_timeouts++;

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
            else
                file_ctx->verdict = FILE_VERDICT_LOG;

            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                "File signature lookup: timed out after %" PRIi64 "ms.\n",
                time_elapsed_ms(&now, &file_ctx->pending_expire_time, cur_lookup_timeout));

            if (PacketTracer::is_active())
            {
                PacketTracer::log("File signature lookup: timed out after %" PRIi64 "ms.\n", time_elapsed_ms(&now, &file_ctx->pending_expire_time, cur_lookup_timeout));
            }
        }
        else
        {
            //  Add packet to retry queue while we wait for response.

            if (!timerisset(&file_ctx->pending_expire_time))
            {
                add_time = { static_cast<time_t>(cur_lookup_timeout), 0 };
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
                    PacketTracer::log("File signature lookup: adding packet to retry queue. Resume=%d, Waited %" PRIi64 "ms.\n", resume, time_elapsed_ms(&now, &file_ctx->pending_expire_time, cur_lookup_timeout));

                    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                        "File signature lookup adding packet to retry queue"
                        "Resume=%d, Waited %" PRIi64 "ms.\n", resume,
                        time_elapsed_ms(&now, &file_ctx->pending_expire_time, cur_lookup_timeout));
                }
            }

            act->set_delayed_action(Active::ACT_RETRY, true);
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                "apply_verdict:FILE_VERDICT_PENDING with action retry\n");
            FileFlows *files = FileFlows::get_file_flows(flow);
            if (files)
            {
               files->add_pending_file(file_ctx->get_file_id());
            }

            if (resume)
                policy->log_file_action(flow, file_ctx, FILE_RESUME_BLOCK);
            else if (store_verdict(flow, file_ctx, cur_lookup_timeout, cache_full, file_ctx->is_cacheable()) != 0)
            {
                if (cache_full)
                {
                    act->set_delayed_action(Active::ACT_RETRY, true);
                    if (PacketTracer::is_active())
                    {
                        PacketTracer::log("apply_verdict:FILE_VERDICT_PENDING with action retry\n");
                    }
                }
                else
                {
                    act->set_delayed_action(Active::ACT_DROP, true);
                    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                        "apply_verdict:FILE_VERDICT_PENDING with action drop\n");
                }
            }
            else if (files)
            {
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
                    "apply_verdict:Adding file id to pending\n");
            }
        }
        return true;
    }
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
    else if (bool is_cacheable = file_ctx->is_cacheable())
    {
        if (store_verdict(flow, file_ctx, block_timeout.load(std::memory_order_relaxed), cache_full, is_cacheable) != 0)
        {
            if (PacketTracer::is_active())
            {
                PacketTracer::log("apply_verdict:storing the file verdict failed\n");
            }
        }
        else
        {
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "apply_verdict:storing the file verdict\n");
        }
    }

    return true;
}

FileVerdict FileCache::cached_verdict_lookup(Packet* p, FileInfo* file,
    FilePolicyBase* policy, const uint8_t* current_data, uint32_t current_data_len)
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

    int64_t lease = lookup_timeout.load(std::memory_order_relaxed);
    FileContext* file_found = find_and_pin(flow, file_id, lease < 1 ? 1 : lease);

    if (file_found)
    {
        CacheNodePin node_pin(cache_mutex, file_found);
        {
            std::lock_guard<std::recursive_mutex> udlock(file_found->user_file_data_mutex);

            if (not static_cast<FileContext*>(file)->is_cache_dup()
                and file_found->verdict == FILE_VERDICT_PENDING)
                return FILE_VERDICT_UNKNOWN;

            file_found->set_partial_flag(file->is_partial_download());
            verdict = check_verdict(p, file_found, policy, current_data, current_data_len);
        }
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "cached_verdict_lookup:Verdict received from cached_verdict_lookup %d\n", verdict);
        file->verdict = verdict;
        if (verdict != FILE_VERDICT_UNKNOWN)
            apply_verdict(p, file_found, verdict, true, policy);
        if (verdict != FILE_VERDICT_UNKNOWN)
        {
            const bool cur_type_enabled = file->is_file_type_enabled();
            const bool cur_sig_enabled = file->is_file_signature_enabled();
            std::lock_guard<std::mutex> lock(cache_mutex);
            std::lock_guard<std::recursive_mutex> udlock(file_found->user_file_data_mutex);
            file->copy(*(FileInfo*)file_found, false);
            file->config_file_type(cur_type_enabled);
            file->config_file_signature(cur_sig_enabled);
        }
    }

    return verdict;
}

FileVerdict FileCache::resume_pending_verdict(Packet* p, FileInfo* dup,
    FilePolicyBase* policy)
{
    Flow* flow = p->flow;
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

    assert(dup);
    uint64_t file_id = dup->get_file_id();
    if (!file_id)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
            "resume_pending_verdict:File id not found, returning\n");
        return verdict;
    }

    int64_t lease = lookup_timeout.load(std::memory_order_relaxed);
    FileContext* node = find_and_pin(flow, file_id, lease < 1 ? 1 : lease);
    if (!node)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "resume_pending_verdict:node not found, returning\n");
        return verdict;
    }

    CacheNodePin node_pin(cache_mutex, node);
    {
        std::lock_guard<std::recursive_mutex> udlock(node->user_file_data_mutex);
        if (dup->is_file_name_set())
            node->set_file_name(dup->get_file_name().c_str(), dup->get_file_name().size());
        if (dup->is_url_set())
            node->set_url(dup->get_url().c_str(), dup->get_url().size());
        if (dup->is_host_set())
            node->set_host(dup->get_host_name().c_str(), dup->get_host_name().size());

        verdict = policy->signature_lookup(p, node);
    }
    dup->verdict = verdict;
    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "resume_pending_verdict:applying file cache verdict %d\n", verdict);
    apply_verdict(p, node, verdict, false, policy);
    const FileVerdict resolved = node->verdict;
    dup->verdict = resolved;
    node->log_file_event(flow, policy);
    {
        const bool cur_type_enabled = dup->is_file_type_enabled();
        const bool cur_sig_enabled = dup->is_file_signature_enabled();
        std::lock_guard<std::mutex> lock(cache_mutex);
        std::lock_guard<std::recursive_mutex> udlock(node->user_file_data_mutex);
        dup->copy(*(FileInfo*)node, false);
        dup->config_file_type(cur_type_enabled);
        dup->config_file_signature(cur_sig_enabled);
    }
    return resolved;
}

namespace
{
// Raw snapshot of the fields dump_cache()/dump_cache_entry() need. Two locks
// are involved: cache_mutex (held by walk_locked) keeps the node itself alive
// for the walk, but the node's user_file_data_mutex is what guards the entry's
// contents -- resume_pending_verdict() rewrites file_name/url/host holding
// only that lock, so copying those std::strings under cache_mutex alone would
// race with a reassignment that frees the buffer being read. verdict is still
// written unlocked by apply_verdict(), so it may be momentarily stale.
// Formatting into display strings is deferred until both locks are released.
struct FileCacheRow
{
    uint8_t sha[SHA256_HASH_SIZE] = {};
    bool has_sha = false;
    std::string name;
    uint32_t type_id = 0;
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

    std::string sha_str;
    std::string type_name;
    std::string verdict_name;
};

struct FileCacheDetailRow : FileCacheRow
{
    uint64_t size = 0;
    bool is_download = false;
    std::string direction;
    uint64_t file_id = 0;
    std::string url;
    std::string host;
};

// Caller must hold cache_mutex and the node's user_file_data_mutex.
void snapshot_common_row(FileCacheRow& row, FileContext* file)
{
    uint8_t* sha = file->get_file_sig_sha256();
    row.has_sha = sha != nullptr;
    if ( row.has_sha )
        memcpy(row.sha, sha, SHA256_HASH_SIZE);

    const std::string& name = file->get_file_name();
    row.name = name.empty() ? "<empty>" : name;

    row.type_id = file->get_file_type();
    row.verdict = file->verdict;
}

inline char hex_digit(uint8_t byte, bool low_nibble)
{
    static const char conv[] = "0123456789ABCDEF";
    return low_nibble ? conv[byte & 0x0F] : conv[(byte >> 4) & 0x0F];
}

std::string sha_to_hex(const uint8_t* digest)
{
    std::string out;
    out.reserve(2 * SHA256_HASH_SIZE);
    for ( unsigned i = 0; i < SHA256_HASH_SIZE; ++i )
    {
        out.push_back(hex_digit(digest[i], false));
        out.push_back(hex_digit(digest[i], true));
    }
    return out;
}

// Allocation-free equivalent of comparing hex_prefix against the leading
// characters of sha_to_hex(sha256). Used under cache_mutex so that
// non-matching entries incur only a cheap byte comparison (no per-node string
// allocation) while the lock is held.
bool sha_hex_prefix_matches(const uint8_t* sha256, const std::string& hex_prefix)
{
    if ( hex_prefix.length() > 2 * SHA256_HASH_SIZE )
        return false;

    for ( size_t i = 0; i < hex_prefix.length(); ++i )
    {
        if ( hex_digit(sha256[i / 2], (i & 1) != 0) != hex_prefix[i] )
            return false;
    }
    return true;
}

// Called after cache_mutex is released: formatting/allocation only.
// When truncate_name is true (default), long file names are shortened for
// column output; pass false for detail output to preserve the full name.
void format_common_row(FileCacheRow& row, bool truncate_name = true)
{
    row.sha_str = row.has_sha ? sha_to_hex(row.sha) : "<pending>";

    if ( truncate_name and row.name.length() > 20 )
        row.name = row.name.substr(0, 17) + "...";

    row.type_name = file_type_name(row.type_id);
    row.verdict_name = VerdictName[row.verdict];
}
}

unsigned FileCache::walk_locked(unsigned max_entries,
    const std::function<bool(FileContext*)>& visit)
{
    std::lock_guard<std::mutex> lock(cache_mutex);

    unsigned total = fileHash ? fileHash->get_num_nodes() : 0;
    if ( !total )
        return 0;

    HashNode* hash_node = fileHash->find_first_node();
    unsigned visited = 0;

    while ( hash_node and visited < max_entries )
    {
        FileNode* node = (FileNode*)hash_node->data;
        if ( node and node->file )
        {
            visited++;
            if ( !visit(node->file) )
                break;
        }
        hash_node = fileHash->find_next_node();
    }

    return total;
}

void FileCache::dump_cache(ControlConn* ctrlcon, unsigned max_entries)
{
    std::vector<FileCacheRow> rows;

    // Field copies only (one short std::string each), under cache_mutex plus
    // the node's user_file_data_mutex.
    unsigned total = walk_locked(max_entries, [&rows](FileContext* file)
    {
        FileCacheRow row;
        {
            std::lock_guard<std::recursive_mutex> udlock(file->user_file_data_mutex);
            snapshot_common_row(row, file);
        }
        rows.emplace_back(std::move(row));
        return true;
    });

    // Formatting/allocation happens here, after cache_mutex is released.
    for ( auto& row : rows )
        format_common_row(row);

    LogRespond(ctrlcon, "\nTotal number of cache entries: %u\n", total);

    if ( !total )
        return;

    LogRespond(ctrlcon, "%-20s | %-10s | %-12s | %s\n",
        "File Name", "File Type", "Verdict", "SHA256");

    for ( const auto& row : rows )
    {
        LogRespond(ctrlcon, "%-20s   %-10s   %-12s   %s\n",
            row.name.c_str(),
            row.type_name.c_str(),
            row.verdict_name.c_str(),
            row.sha_str.c_str());
    }

    if ( rows.size() < total )
        LogRespond(ctrlcon, "... displayed %zu of %u entries\n", rows.size(), total);
}

void FileCache::dump_cache_entry(ControlConn* ctrlcon, const std::string& sha_hex)
{
    std::vector<FileCacheDetailRow> rows;

    // Per-node work is one allocation-free SHA prefix comparison; every entry
    // whose SHA matches the prefix is copied (the same file seen on multiple
    // flows yields multiple cache entries sharing a SHA). Each copy is done
    // holding the node's user_file_data_mutex so the row is internally
    // consistent and the string copies cannot race with a concurrent
    // set_url()/set_host(). All hex/string formatting is deferred until after
    // the locks are released.
    unsigned total = walk_locked(std::numeric_limits<unsigned>::max(), [&](FileContext* file)
    {
        std::lock_guard<std::recursive_mutex> udlock(file->user_file_data_mutex);
        uint8_t* sha = file->get_file_sig_sha256();
        if ( !sha )
            return true;

        if ( !sha_hex_prefix_matches(sha, sha_hex) )
            return true;

        FileCacheDetailRow row;
        snapshot_common_row(row, file);
        row.size = file->get_file_size();
        row.is_download = file->get_file_direction() == FILE_DOWNLOAD;
        row.file_id = file->get_file_id();
        row.url = file->get_url();
        row.host = file->get_host_name();

        rows.emplace_back(std::move(row));
        return true;
    });

    if ( rows.empty() )
    {
        if ( !total )
            LogRespond(ctrlcon, "File cache is empty\n");
        else
            LogRespond(ctrlcon, "No cache entry found matching SHA256: %s\n", sha_hex.c_str());
        return;
    }

    for ( auto& row : rows )
    {
        format_common_row(row, false);
        row.direction = row.is_download ? "Download" : "Upload";

        LogRespond(ctrlcon, "\nSHA256: %s\n", row.sha_str.c_str());
        LogRespond(ctrlcon, "File Name: %s\n", row.name.c_str());
        LogRespond(ctrlcon, "File Type: %s (id: %u)\n", row.type_name.c_str(), row.type_id);
        LogRespond(ctrlcon, "File Size: %" PRIu64 "\n", row.size);
        LogRespond(ctrlcon, "Verdict: %s\n", row.verdict_name.c_str());
        LogRespond(ctrlcon, "Direction: %s\n", row.direction.c_str());
        LogRespond(ctrlcon, "File ID: %" PRIu64 "\n", row.file_id);

        if ( !row.url.empty() )
            LogRespond(ctrlcon, "URL: %s\n", row.url.c_str());

        if ( !row.host.empty() )
            LogRespond(ctrlcon, "Host: %s\n", row.host.c_str());
    }
}
