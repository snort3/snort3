//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/*!
    \file sfthd.h
*/
#ifndef SFTHD_H
#define SFTHD_H

#include "framework/counts.h"
#include "main/policy.h"
#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"

#include <mutex>
#include <vector>

namespace snort
{
class GHash;
class XHash;
struct SnortConfig;
}

typedef struct sf_list SF_LIST;

static std::mutex sfthd_hash_mutex;

/*!
    Max GEN_ID value - Set this to the Max Used by Snort, this is used for the
    dimensions of the gen_id lookup array.

    Rows in each hash table, by gen_id.
*/
#define THD_MAX_GENID     8129
#define THD_GEN_ID_1_ROWS 4096
#define THD_GEN_ID_ROWS   512

#define THD_NO_THRESHOLD (-1)

#define THD_TOO_MANY_THDOBJ (-15)

/*!
   Type of Thresholding
*/
enum
{
    THD_TYPE_LIMIT,
    THD_TYPE_THRESHOLD,
    THD_TYPE_BOTH,
    THD_TYPE_SUPPRESS,
    THD_TYPE_DETECT
};

/*
   Very high priority for suppression objects
   users priorities are limited to this minus one
*/
#define THD_PRIORITY_SUPPRESS 1000000

/*!
   Tracking by src, or by dst
*/
enum
{
    THD_TRK_NONE,  // suppress only
    THD_TRK_SRC,
    THD_TRK_DST
};

/*!
    THD_IP_NODE

    Dynamic hashed node data - added and deleted during runtime
    These are added during run-time, and recycled if we max out memory usage.
*/
struct THD_IP_NODE
{
    unsigned count;
    unsigned prev;
    time_t tstart;
    time_t tlast;
};

/*!
    THD_IP_NODE_KEY

    HASH Key to lookup and store Ip nodes. The structure now tracks thresholds for different
    policies. This destroys locality of reference and may cause poor performance.
*/
PADDING_GUARD_BEGIN
struct THD_IP_NODE_KEY
{
    int thd_id;
    PolicyId policyId;
    snort::SfIp ip;
    uint16_t padding;
};

struct THD_IP_GNODE_KEY
{
    unsigned gen_id;
    unsigned sig_id;
    PolicyId policyId;
    snort::SfIp ip;
    uint16_t padding;
};
PADDING_GUARD_END

/*!
    A Thresholding Object
    These are created at program startup, and remain static.
    The THD_IP_NODE elements are dynamic.
*/
struct THD_NODE
{
    int thd_id = 0;        /* Id of this node */
    unsigned gen_id = 0;   /* Keep these around if needed */
    unsigned sig_id = 0;
    int tracking = 0;      /* by_src, by_dst */
    int type = 0;
    int priority = 0;
    int count = 0;
    unsigned seconds = 0;
    sfip_var_t* ip_address = nullptr;
};

/*!
    The THD_ITEM acts as a container of gen_id+sig_id based threshold objects,
    this allows multiple threshold objects to be applied to a single
    gen_id+sig_id pair. The sflist is created using the priority field,
    so highest priority objects are first in the list. When processing the
    highest priority object will trigger first.

    These are static data elements, built at program startup.
*/
struct THD_ITEM
{
    PolicyId policyId;
    unsigned gen_id; /* just so we know what gen_id we are */
    unsigned sig_id;
    /*
     * List of THD_NODE's - walk this list and hash the
     * 'THD_NODE->sfthd_id + src_ip or dst_ip' to get the correct THD_IP_NODE.
     */
    SF_LIST* sfthd_node_list;
};

// Temporary structure useful when parsing the Snort rules
struct THDX_STRUCT
{
    unsigned gen_id;
    unsigned sig_id;
    unsigned seconds;

    int type;
    int count;
    int tracking;
    int priority;

    sfip_var_t* ip_address;
};

struct tThdItemKey
{
    PolicyId policyId;
    unsigned sig_id;
};

/*!
    THD_STRUCT

    The main thresholding data structure.

    Local and global threshold thd_id's are all unique, so we use just one
    ip_nodes lookup table
 */
struct THD_STRUCT
{
    snort::XHash* ip_nodes;   /* Global hash of active IP's key=THD_IP_NODE_KEY, data=THD_IP_NODE */
    snort::XHash* ip_gnodes;  /* Global hash of active IP's key=THD_IP_GNODE_KEY, data=THD_IP_GNODE */
};

struct ThresholdObjects
{
    int count = 0;  /* Total number of thresholding/suppression objects */
    std::vector<snort::GHash*> sfthd_vector;    /* Local Hash of THD_ITEM nodes,  lookup by key=sig_id */
    /*
    * Vector of unordered maps, each map indexed by generator ID (genId) and containing 
    * unique pointers to THD_NODE structures. The outer vector is indexed by policyId 
    * and can dynamically vary in size. Each map represents THD_NODE structures for a specific 
    * policyId, with the key being the genId. This allows direct access to THD_NODE structures 
    * by their generator ID within a given policy context, optimizing lookup and management 
    * of thresholding nodes.
    */
    std::vector<std::unordered_map<uint32_t, std::unique_ptr<THD_NODE>>> sfthd_gvector;

    PolicyId numPoliciesAllocated = 0;
};

struct EventFilterStats
{
    PegCount xhash_nomem_peg_local = 0;
    PegCount xhash_nomem_peg_global = 0;
};

/*
 * Prototypes
 */
// lbytes = local threshold memcap
// gbytes = global threshold memcap (0 to disable global)
THD_STRUCT* sfthd_new(unsigned lbytes, unsigned gbytes);
snort::XHash* sfthd_local_new(unsigned bytes);
snort::XHash* sfthd_global_new(unsigned bytes);
void sfthd_free(THD_STRUCT*);
ThresholdObjects* sfthd_objs_new();
void sfthd_objs_free(ThresholdObjects*);

int sfthd_test_rule(snort::XHash* rule_hash, THD_NODE* sfthd_node,
    const snort::SfIp* sip, const snort::SfIp* dip, long curtime, PolicyId policy_id);

THD_NODE* sfthd_create_rule_threshold(
    int id,
    int tracking,
    int type,
    int count,
    unsigned int seconds
    );
void sfthd_node_free(THD_NODE*);

int sfthd_create_threshold(snort::SnortConfig*, ThresholdObjects*, unsigned gen_id,
    unsigned sig_id, int tracking, int type, int priority, int count,
    unsigned seconds, sfip_var_t* ip_address, PolicyId policy_id);

//  1: don't log due to event_filter
//  0: log
// -1: don't log due to suppress
int sfthd_test_threshold(ThresholdObjects*, THD_STRUCT*, unsigned gen_id, unsigned sig_id,
    const snort::SfIp* sip, const snort::SfIp* dip, long curtime, PolicyId policy_id);

snort::XHash* sfthd_new_hash(unsigned, size_t, size_t);

int sfthd_test_local(snort::XHash* local_hash, THD_NODE* sfthd_node, const snort::SfIp* sip,
    const snort::SfIp* dip, time_t curtime, PolicyId policy_id);

#ifdef THD_DEBUG
int sfthd_show_objects(THD_STRUCT* thd);
#endif

#endif
