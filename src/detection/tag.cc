//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// Chris Green <cmg@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tag.h"

#include "detection/ips_context.h"
#include "events/event.h"
#include "hash/hash_defs.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "trace/trace_api.h"
#include "utils/cpp_macros.h"
#include "utils/util.h"

#include "treenodes.h"

#include "detect_trace.h"

using namespace snort;

/*  D E F I N E S  **************************************************/
#define MAX_TAG_NODES   256

/* by default we'll set a 5 minute timeout if we see no activity
 * on a tag with a 'count' metric so that we prune dead sessions
 * periodically since we're not doing TCP state tracking
 */
#define TAG_PRUNE_QUANTUM   300
#define TAG_MEMCAP          4194304  /* 4MB */

/*  D A T A   S T R U C T U R E S  **********************************/
/**Key used for identifying a session or host.
 */
PADDING_GUARD_BEGIN
struct tTagFlowKey
{
    SfIp sip;  ///source IP address
    SfIp dip;  ///destination IP address

    /* ports */
    uint16_t sp; ///source port
    uint16_t dp; ///destination port
};
PADDING_GUARD_END

/**Node identifying a session or host based tagging.
 */
struct TagNode
{
    /**key identifying a session or host. */
    tTagFlowKey key;

    /** number of packets/seconds/bytes to tag for */
    int seconds;
    int packets;
    int bytes;

    /** counters of number of packets tagged and max to
     * prevent Eventing DOS */
    int pkt_count;

    /** packets/seconds selector */
    int metric;

    /** session or host mode */
    int mode;

    /** last UNIX second that this node had a successful match */
    uint32_t last_access;

    /** event id number for correlation with trigger events */
    uint16_t event_id;
    struct timeval event_time;

    struct ListHead* log_list;  // retain custom logging if any from triggering alert
};

/*  G L O B A L S  **************************************************/
static THREAD_LOCAL uint32_t last_prune_time = 0;
static THREAD_LOCAL uint32_t tag_alloc_faults = 0;
static THREAD_LOCAL uint32_t tag_memory_usage = 0;

static THREAD_LOCAL bool s_exclusive = false;
static THREAD_LOCAL unsigned s_sessions = 0;

// TBD when tags leverage sessions, tag nodes can be freed at end
// of session.  then we can configure this to allow multiple
// (consecutive) sessions to be captured.
static const unsigned s_max_sessions = 1;

/*  P R O T O T Y P E S  ********************************************/
static void TagFree(XHash*, TagNode*);
static int PruneTagCache(uint32_t, int);

class TagSessionCache : public XHash
{
public:
    TagSessionCache(int rows, int key_len)
        : XHash(rows, key_len)
    {
        initialize();
        anr_enabled = false;
        recycle_nodes = false;
    }

    ~TagSessionCache() override
    {
        delete_hash_table();
    }

    void free_user_data(HashNode* hnode) override
    {
        TagFree(this, (TagNode*)hnode->data);
    }
};

class TagHostCache : public XHash
{
public:
    TagHostCache(int rows, int key_len)
        : XHash(rows, key_len)
    {
        initialize();
        anr_enabled = false;
        recycle_nodes = false;
    }

    ~TagHostCache() override
    {
        delete_hash_table();
    }

    void free_user_data(HashNode* hnode) override
    {
        TagFree(this, (TagNode*)hnode->data);
    }
};

static THREAD_LOCAL TagHostCache* host_tag_cache = nullptr;

// FIXIT-M utilize Flow instead of separate cache
static THREAD_LOCAL TagSessionCache* ssn_tag_cache = nullptr;


/**Calculated memory needed per node insertion into respective cache. Its includes
 * memory needed for allocating TagNode, HashNode and key size.
 *
 * @param hash - pointer to XHash that should point to either ssn_tag_cache_ptr
 * or host_tag_cache_ptr.
 *
 * @returns number of bytes needed
 */
static inline unsigned int memory_per_node(const XHash* hash)
{
    if ( hash == ssn_tag_cache )
        return sizeof(tTagFlowKey) + sizeof(HashNode) + sizeof(TagNode);
    else if ( hash == host_tag_cache )
        return sizeof(SfIp) + sizeof(HashNode) + sizeof(TagNode);

    return 0;
}

/** Allocate a TagNode
 *
 * Allocates a TagNode while guaranteeing that total memory usage remains within TAG_MEMCAP.
 * Least used nodes may be deleted from ssn_tag_cache and host_tag_cache to make space if
 * the limit is being exceeded.
 *
 * @param hash - pointer to XHash that should point to either ssn_tag_cache_ptr
 * or host_tag_cache_ptr.
 *
 * @returns a pointer to new TagNode or null if memory couldn't * be allocated
 */
static TagNode* TagAlloc(
    XHash* hash
    )
{
    TagNode* tag_node = nullptr;

    if (tag_memory_usage + memory_per_node(hash) > TAG_MEMCAP)
    {
        /* aggressively prune */
        struct timeval tv;
        struct timezone tz;
        int pruned_nodes = 0;

        tag_alloc_faults++;

        gettimeofday(&tv, &tz);

        pruned_nodes = PruneTagCache((uint32_t)tv.tv_sec, 0);

        if (pruned_nodes == 0)
        {
            /* if we can't prune due to time, just try to nuke
             * 5 not so recently used nodes */
            pruned_nodes = PruneTagCache(0, 5);

            /* unlikely to happen since memcap has been reached */
            if (pruned_nodes == 0)
                return nullptr;
        }
    }

    tag_node = (TagNode*)snort_calloc(sizeof(TagNode));
    tag_memory_usage += memory_per_node(hash);

    return tag_node;
}

static void TagFree(XHash* hash, TagNode* node)
{
    if (node == nullptr)
        return;

    if ( node->metric & TAG_METRIC_SESSION )
        s_exclusive = false;

    snort_free((void*)node);
    tag_memory_usage -= memory_per_node(hash);
}

static inline void SwapTag(TagNode* np)
{
    SfIp tip;
    uint16_t tport;

    tip = np->key.sip;
    np->key.sip = np->key.dip;
    np->key.dip = tip;

    tport = np->key.sp;
    np->key.sp = np->key.dp;
    np->key.dp = tport;
}

void InitTag()
{
    unsigned int hashTableSize = TAG_MEMCAP/sizeof(TagNode);

    ssn_tag_cache = new TagSessionCache(hashTableSize, sizeof(tTagFlowKey));
    host_tag_cache = new TagHostCache(hashTableSize, sizeof(SfIp));
}

void CleanupTag()
{
    delete ssn_tag_cache;
    delete host_tag_cache;
}

static void AddTagNode(const Packet* p, TagData* tag, int mode, uint32_t now,
    uint16_t event_id, ListHead* log_list)
{
    TagNode* idx;  /* index pointer */
    TagNode* returned;
    XHash* tag_cache_ptr = nullptr;

    debug_log(detection_trace, TRACE_TAG, p, "Adding new Tag Head\n");

    if ( tag->tag_metric & TAG_METRIC_SESSION )
    {
        if ( s_exclusive )
            return;

        if ( s_sessions >= s_max_sessions )
            return;

        s_exclusive = true;
        ++s_sessions;
    }
    if (mode == TAG_SESSION)
    {
        tag_cache_ptr = ssn_tag_cache;
    }
    else
    {
        tag_cache_ptr = host_tag_cache;
    }
    idx = TagAlloc(tag_cache_ptr);

    /* If a TagNode couldn't be allocated, just write an error message
     * and return - won't be able to track this one. */
    if (idx == nullptr)
    {
        ErrorMessage("AddTagNode(): Unable to allocate %u bytes of memory for new TagNode\n",
            (unsigned)sizeof(TagNode));
        return;
    }

    idx->key.sip = *p->ptrs.ip_api.get_src();
    idx->key.dip = *p->ptrs.ip_api.get_dst();
    idx->key.sp = p->ptrs.sp;
    idx->key.dp = p->ptrs.dp;
    idx->metric = tag->tag_metric;
    idx->last_access = now;
    idx->event_id = event_id;
    idx->event_time.tv_sec = p->pkth->ts.tv_sec;
    idx->event_time.tv_usec = p->pkth->ts.tv_usec;
    idx->mode = mode;
    idx->pkt_count = 0;
    idx->log_list = log_list;

    if (idx->metric & TAG_METRIC_SECONDS)
    {
        /* set the expiration time for this tag */
        idx->seconds = now + tag->tag_seconds;
    }

    if (idx->metric & TAG_METRIC_BYTES)
    {
        /* set the expiration time for this tag */
        idx->bytes = tag->tag_bytes;
    }

    if (idx->metric & TAG_METRIC_PACKETS)
    {
        /* set the expiration time for this tag */
        idx->packets = tag->tag_packets;
    }

    /* check for duplicates */
    returned = (TagNode*)tag_cache_ptr->get_user_data(idx);

    if (returned == nullptr)
    {
        SwapTag(idx);
        returned = (TagNode*)tag_cache_ptr->get_user_data(idx);
        SwapTag(idx);
    }

    if (returned == nullptr)
    {
        /* if we're supposed to be tagging the other side, swap it
           around -- Lawrence Reed */
        if (mode == TAG_HOST_DST)
        {
            SwapTag(idx);
        }

        if (tag_cache_ptr->insert(idx, idx) != HASH_OK)
        {
            TagFree(tag_cache_ptr, idx);
            return;
        }
    }
    else
    {
        if (idx->metric & TAG_METRIC_SECONDS)
            returned->seconds = idx->seconds;
        else
            returned->seconds += idx->seconds;

        /* get rid of the new tag since we are using an existing one */
        TagFree(tag_cache_ptr, idx);
    }
}

static void TagSession(const Packet* p, TagData* tag, uint32_t time, uint16_t event_id, ListHead* log_list)
{
    AddTagNode(p, tag, TAG_SESSION, time, event_id, log_list);
}

static void TagHost(const Packet* p, TagData* tag, uint32_t time, uint16_t event_id, ListHead* log_list)
{
    int mode;

    switch (tag->tag_direction)
    {
    case TAG_HOST_DST:
        mode = TAG_HOST_DST;
        break;
    case TAG_HOST_SRC:
        mode = TAG_HOST_SRC;
        break;
    default:
        mode = TAG_HOST_SRC;
        break;
    }

    AddTagNode(p, tag, mode, time, event_id, log_list);
}

int CheckTagList(
    Packet* p, SigInfo& info, ListHead*& ret_list, struct timeval& ret_time, uint32_t& ret_id, const char*& ret_act)
{
    TagNode idx;
    TagNode* returned = nullptr;
    XHash* taglist = nullptr;
    char create_event = 1;

    /* check for active tags */
    if (!host_tag_cache->get_num_nodes() && !ssn_tag_cache->get_num_nodes())
    {
        return 0;
    }

    if(p == nullptr || !p->ptrs.ip_api.is_ip())
    {
        return 0;
    }

    idx.key.sip = *p->ptrs.ip_api.get_src();
    idx.key.dip = *p->ptrs.ip_api.get_dst();
    idx.key.sp = p->ptrs.sp;
    idx.key.dp = p->ptrs.dp;

    /* check for session tags... */
    returned = (TagNode*)ssn_tag_cache->get_user_data(&idx);

    if (returned == nullptr)
    {
        idx.key.dip = *p->ptrs.ip_api.get_src();
        idx.key.sip = *p->ptrs.ip_api.get_dst();
        idx.key.dp = p->ptrs.sp;
        idx.key.sp = p->ptrs.dp;

        returned = (TagNode*)ssn_tag_cache->get_user_data(&idx);

        if (returned == nullptr)
        {
            returned = (TagNode*)host_tag_cache->get_user_data(&idx);

            if (returned == nullptr)
            {
                /*
                **  Only switch sip, because that's all we check for
                **  the host tags.
                */
                idx.key.sip = *p->ptrs.ip_api.get_src();

                returned = (TagNode*)host_tag_cache->get_user_data(&idx);
            }

            if (returned != nullptr)
            {
                taglist = host_tag_cache;
            }
        }
        else
        {
            taglist = ssn_tag_cache;
        }
    }
    else
    {
        taglist = ssn_tag_cache;
    }

    if (returned != nullptr)
    {
        returned->last_access = p->pkth->ts.tv_sec;
        returned->pkt_count++;

        if ( returned->metric & TAG_METRIC_SECONDS )
        {
            if (p->pkth->ts.tv_sec > returned->seconds)
            {
                returned->metric = 0;
                create_event = 0;
            }
        }

        if ( returned->metric & TAG_METRIC_BYTES )
        {
            int n = p->pktlen;
            if ( n < returned->bytes )
                returned->bytes -= n;
            else
                returned->metric = 0;
        }

        if ( returned->metric & TAG_METRIC_PACKETS )
        {
            if ( returned->packets > 1 )
                returned->packets--;
            else
                returned->metric = 0;
        }

        if ( !(returned->metric & TAG_METRIC_UNLIMITED) )
        {
            /* Check whether or not to actually log an event.
             * This is used to prevent a poorly written tag rule
             * from DOSing a backend event processors on high
             * bandwidth sensors. */
            /* Use the global max.
               If its non-0, check count for this tag node */
            if ( p->context->conf->get_tagged_packet_limit() &&
                returned->pkt_count >= p->context->conf->get_tagged_packet_limit() )
            {
                returned->metric = 0;
            }
        }

        if ( create_event )
        {
            info.gid = GID_TAG;
            info.sid = TAG_LOG_PKT;
            info.rev = 1;
            info.class_id = 1;
            info.priority = 1;

            ret_time = returned->event_time;
            ret_id = returned->event_id;
            ret_list = returned->log_list;
            ret_act = (ret_list and ret_list->ruleListNode) ? ret_list->ruleListNode->name : "";
        }

        if ( !returned->metric )
        {
            if (taglist->release_node(&returned->key) != HASH_OK)
            {
                LogMessage("WARNING: failed to remove tagNode from hash.\n");
            }
        }
    }

    if ( (unsigned)(p->pkth->ts.tv_sec) > last_prune_time + TAG_PRUNE_QUANTUM )
    {
        PruneTagCache(p->pkth->ts.tv_sec, 0);
        last_prune_time = p->pkth->ts.tv_sec;
    }

    if ( returned && create_event )
        return 1;

    return 0;
}

static int PruneTime(XHash* tree, uint32_t thetime)
{
    int pruned = 0;
    TagNode* lru_node = nullptr;

    while ((lru_node = (TagNode*)tree->get_lru_user_data()) != nullptr)
    {
        if ((lru_node->last_access + TAG_PRUNE_QUANTUM) < thetime)
        {
            if (tree->release_node(&lru_node->key) != HASH_OK)
            {
                LogMessage("WARNING: failed to remove tagNode from hash.\n");
            }
            pruned++;
        }
        else
        {
            break;
        }
    }

    return pruned;
}

static int PruneTagCache(uint32_t thetime, int mustdie)
{
    int pruned = 0;

    if (mustdie == 0)
    {
        if (ssn_tag_cache->get_num_nodes() != 0)
            pruned = PruneTime(ssn_tag_cache, thetime);

        if (host_tag_cache->get_num_nodes() != 0)
            pruned += PruneTime(host_tag_cache, thetime);
    }
    else
    {
        while (pruned < mustdie &&
            (ssn_tag_cache->get_num_nodes() > 0 || host_tag_cache->get_num_nodes() > 0))
        {
            if ( ssn_tag_cache->delete_lru_node() )
                ++pruned;
            else
                LogMessage("WARNING: failed to remove tagNode from ssn hash.\n");

            if ( host_tag_cache->delete_lru_node() )
                ++pruned;
            else
                LogMessage("WARNING: failed to remove tagNode from host hash.\n");
        }
    }

    return pruned;
}

void SetTags(const Packet* p, const OptTreeNode* otn, uint16_t event_id)
{
    if (otn != nullptr && otn->tag != nullptr)
    {
        if (otn->tag->tag_type != 0)
        {
            RuleTreeNode* rtn = getRtnFromOtn(otn);
            ListHead* log_list = rtn ? rtn->listhead : nullptr;

            switch (otn->tag->tag_type)
            {
            case TAG_SESSION:
                TagSession(p, otn->tag, p->pkth->ts.tv_sec, event_id, log_list);
                break;
            case TAG_HOST:
                TagHost(p, otn->tag, p->pkth->ts.tv_sec, event_id, log_list);
                break;

            default:
                LogMessage("WARNING: Trying to tag with unknown "
                    "tag type.\n");
                break;
            }
        }
    }
}

