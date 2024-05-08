//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

/*
 * sfthd.cc author Marc Norton
 *
 * An Abstracted Event Thresholding System
 * 01/24/2024 -  updated the arrays with STL containers (Raza Shafiq: rshafiq@cisco.com)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfthd.h"

#include <cassert>
#include <set>

#include "hash/ghash.h"
#include "hash/hash_defs.h"
#include "hash/xhash.h"
#include "sfip/sf_ipvar.h"
#include "utils/sflsq.h"
#include "utils/util.h"

using namespace snort;

THREAD_LOCAL EventFilterStats event_filter_stats;

XHash* sfthd_new_hash(unsigned nbytes, size_t key, size_t data)
{
    size_t size = key + data;
    int nrows;

    /* Calc max ip nodes for this memory */
    if ( nbytes < size )
        nbytes = size;
    nrows = nbytes / size;

    return new XHash(nrows, key, data, nbytes);
}

/*!
  Create a threshold table, initialize the threshold system,
  and optionally limit it's memory usage.

  @param nbytes maximum memory to use for thresholding objects, in bytes.

  @return  THD_STRUCT*
  @retval  0 error
  @retval !0 valid THD_STRUCT
*/

XHash* sfthd_local_new(unsigned bytes)
{
    XHash* local_hash =
        sfthd_new_hash(bytes,
        sizeof(THD_IP_NODE_KEY),
        sizeof(THD_IP_NODE));

    return local_hash;
}

XHash* sfthd_global_new(unsigned bytes)
{
    XHash* global_hash =
        sfthd_new_hash(bytes,
        sizeof(THD_IP_GNODE_KEY),
        sizeof(THD_IP_NODE));

    return global_hash;
}

THD_STRUCT* sfthd_new(unsigned lbytes, unsigned gbytes)
{
    THD_STRUCT* thd;

    /* Create the THD struct */
    thd = (THD_STRUCT*)snort_calloc(sizeof(THD_STRUCT));

    /* Create hash table for all of the local IP Nodes */
    thd->ip_nodes = sfthd_local_new(lbytes);
    if ( !thd->ip_nodes )
    {
        snort_free(thd);
        return nullptr;
    }

    if ( gbytes == 0 )
        return thd;

    /* Create hash table for all of the global IP Nodes */
    thd->ip_gnodes = sfthd_global_new(gbytes);
    if ( !thd->ip_gnodes )
    {
        delete thd->ip_nodes;
        snort_free(thd);
        return nullptr;
    }

    return thd;
}

ThresholdObjects* sfthd_objs_new()
{
    return new ThresholdObjects;
}

void sfthd_node_free(THD_NODE* sfthd_node)
{
    if ( !sfthd_node )
        return;

    if ( sfthd_node->ip_address )
    {
        sfvar_free(sfthd_node->ip_address);
        sfthd_node->ip_address = nullptr;
    }
    delete sfthd_node;
}

static void sfthd_node_free(void* node)
{ sfthd_node_free((THD_NODE*)node); }

void sfthd_objs_free(ThresholdObjects* thd_objs)
{
    if ( thd_objs == nullptr )
        return;

    for ( const auto* hash : thd_objs->sfthd_vector )
    {
        if ( hash )
            delete hash;
    }

    std::set<sfip_var_t*> deleted_ip_vars;
    for (auto& policy_map : thd_objs->sfthd_gvector)
    {
        for (auto& gen_id_and_node : policy_map)
        {
            THD_NODE* node = gen_id_and_node.second.get();
            if ( node )
            {
                auto ip_deleted = deleted_ip_vars.insert(node->ip_address);
                if ( ip_deleted.second ) 
                    sfvar_free(node->ip_address);
            }
        }
        // Clear the map after handling ip_address in all nodes.
        policy_map.clear();
    }

    // If there's anything else in thd_objs that needs manual deletion or cleanup, do it here.

    delete thd_objs;  // Finally, delete the container itself if necessary.
}



static void sfthd_item_free(void* item)
{
    THD_ITEM* sfthd_item = (THD_ITEM*)item;
    sflist_free_all(sfthd_item->sfthd_node_list, sfthd_node_free);
    delete sfthd_item;
}

void sfthd_free(THD_STRUCT* thd)
{
    if ( thd == nullptr )
        return;

    if ( thd->ip_nodes )
        delete thd->ip_nodes;

    if ( thd->ip_gnodes )
        delete thd->ip_gnodes;

    snort_free(thd);
}

THD_NODE* sfthd_create_rule_threshold(int id,
    int tracking,
    int type,
    int count,
    unsigned int seconds)
{
    THD_NODE* sfthd_node = new THD_NODE();
    
    sfthd_node->thd_id    = id;
    sfthd_node->tracking  = tracking;
    sfthd_node->type      = type;
    sfthd_node->count     = count;
    sfthd_node->seconds   = seconds;

    return sfthd_node;
}

/*!
Add a permanent threshold object to the threshold table. Multiple
objects may be defined for each gen_id and sig_id pair. Internally
a unique threshold id is generated for each pair.

Threshold objects track the number of events seen during the time
interval specified by seconds. Depending on the type of threshold
object and the count value, the thresholding object determines if
the current event should be logged or dropped.

@param thd Threshold object from sfthd_new()
@param gen_id Generator id
@param sig_id Signature id
@param tracking Selects tracking by src ip or by dst ip
@param type  Thresholding type: Limit, Threshold, or Limit+Threshold, Suppress
@param priority Assigns a relative priority to this object, higher numbers imply higher priority

@param count Number of events
@param seconds Time duration over which this threshold object acts.
@param ip      IP address, for suppression
@param ip-mask IP mask, applied with ip_mask, for suppression

@return integer
@retval  0 successfully added the thresholding object
@retval !0 failed
*/
static int sfthd_create_threshold_local(
    SnortConfig*, ThresholdObjects* thd_objs, THD_NODE* config, PolicyId policy_id)
{
    
    if ( thd_objs == nullptr or config == nullptr )
        return -1;
    
    if ( config->gen_id >= THD_MAX_GENID )
        return -1;
    
    if ( thd_objs->sfthd_vector.size() <= config->gen_id )
        thd_objs->sfthd_vector.resize(config->gen_id + 1, nullptr);
    
    auto& sfthd_hash = thd_objs->sfthd_vector[config->gen_id];
    if ( sfthd_hash == nullptr )
    {
        int nrows = (config->gen_id == 1) ? THD_GEN_ID_1_ROWS : THD_GEN_ID_ROWS;
        sfthd_hash = new GHash(nrows, sizeof(tThdItemKey), false, sfthd_item_free);
    }

    tThdItemKey key;
    key.sig_id = config->sig_id;
    key.policyId = policy_id;

    
    THD_ITEM* sfthd_item = static_cast<THD_ITEM*>(sfthd_hash->find(&key));
    if ( !sfthd_item )
    {
        sfthd_item = new THD_ITEM{ policy_id, config->gen_id, config->sig_id, sflist_new() };
        if ( sfthd_item->sfthd_node_list == nullptr )
        {
            delete sfthd_item;
            return -4;
        }

        if ( sfthd_hash->insert(&key, sfthd_item) != HASH_OK )
        {
            sflist_free_all(sfthd_item->sfthd_node_list, sfthd_node_free);
            delete sfthd_item;
            return -5;
        }
    }
    /*
     * Test that we only have one Limit/Threshold/Both Object at the tail,
     * we can have multiple suppression nodes at the head
     */
    if ( sfthd_item->sfthd_node_list->count > 0 )
    {
        THD_NODE* p;
        if ( !sfthd_item->sfthd_node_list->tail )
        {
            // Paranoid check: if there is a count, there should be a tail
            return -10;
        }
        p = static_cast<THD_NODE*>(sfthd_item->sfthd_node_list->tail->ndata);
        if ( p ) // Ensure there is node data if there is a tail
        {
            if ( p->type != THD_TYPE_SUPPRESS and config->type != THD_TYPE_SUPPRESS )
            {
                // Cannot add more than one threshold per sid in version 3.0
                return THD_TOO_MANY_THDOBJ;
            }
        }
    }

    THD_NODE* sfthd_node = new THD_NODE(*config);  // Copy the node parameters
    if ( config->priority >= THD_PRIORITY_SUPPRESS )
        sfthd_node->priority = THD_PRIORITY_SUPPRESS - 1;

    if ( sfthd_item->sfthd_node_list->count > 0 )
    {
        SF_LNODE* lnode;
        for ( auto ndata = sflist_first(sfthd_item->sfthd_node_list, &lnode);
             ndata != nullptr; ndata = sflist_next(&lnode) )
        {
            THD_NODE* sfthd_n = static_cast<THD_NODE*>(ndata);
            if ( sfthd_node->priority > sfthd_n->priority )
            {
                sflist_add_before(sfthd_item->sfthd_node_list, lnode, sfthd_node);
                return 0;
            }

            if ( lnode->next == nullptr )
            {
                sflist_add_tail(sfthd_item->sfthd_node_list, sfthd_node);
                return 0;
            }
        }
        delete sfthd_node;
        return -11;
    }
    else
        sflist_add_head(sfthd_item->sfthd_node_list, sfthd_node);

    return 0;
}

/*
 */
static int sfthd_create_threshold_global(
    SnortConfig*, ThresholdObjects* thd_objs, THD_NODE* config, PolicyId policy_id)
{
    if ( thd_objs == nullptr or config == nullptr or config->gen_id >= THD_MAX_GENID )
        return -1;

    if ( thd_objs->sfthd_gvector.size() <= policy_id )
        thd_objs->sfthd_gvector.resize(policy_id + 1);

    auto& map = thd_objs->sfthd_gvector[policy_id];

    // Check if there is an existing entry for config->gen_id
    if ( config->gen_id == 0 and map.find(0) != map.end() )
        map.erase(config->gen_id);

    if ( map.find(config->gen_id) != map.end() )
            return THD_TOO_MANY_THDOBJ;

    map.emplace(config->gen_id, std::make_unique<THD_NODE>(*config));

    return 0;
}

/*!
Add a permanent threshold object to the threshold table. Multiple
objects may be defined for each gen_id and sig_id pair. Internally
a unique threshold id is generated for each pair.

Threshold objects track the number of events seen during the time
interval specified by seconds. Depending on the type of threshold
object and the count value, the thresholding object determines if
the current event should be logged or dropped.

@param thd Threshold object from sfthd_new()
@param gen_id Generator id
@param sig_id Signature id
@param tracking Selects tracking by src ip or by dst ip
@param type  Thresholding type: Limit, Threshold, or Limit+Threshold, Suppress
@param priority Assigns a relative priority to this object, higher numbers imply higher priority

@param count Number of events
@param seconds Time duration over which this threshold object acts.
@param ip      IP address, for suppression
@param ip-mask IP mask, applied with ip_mask, for suppression

@return integer
@retval  0 successfully added the thresholding object
@retval !0 failed

 --- Local and Global Thresholding is setup here  ---

*/
int sfthd_create_threshold(
    SnortConfig* sc,
    ThresholdObjects* thd_objs,
    unsigned gen_id,
    unsigned sig_id,
    int tracking,
    int type,
    int priority,
    int count,
    unsigned seconds,
    sfip_var_t* ip_address, PolicyId policy_id)
{
    
    if ( thd_objs == nullptr ) 
        return -1;

    if ( thd_objs->sfthd_gvector.size() <= policy_id ) 
        thd_objs->sfthd_gvector.resize(policy_id + 1);

    if ( thd_objs->sfthd_vector.size() <= gen_id ) 
        thd_objs->sfthd_vector.resize(gen_id + 1, nullptr);

    THD_NODE sfthd_node { thd_objs->count++, // Increment count and use it as thd_id
    gen_id, sig_id, tracking, // by_src, by_dst
    type, priority, count, seconds, ip_address };
    
    if ( sig_id == 0 )
        return sfthd_create_threshold_global(sc, thd_objs, &sfthd_node, policy_id);

    if ( gen_id == 0 ) 
        return -1;

    return sfthd_create_threshold_local(sc, thd_objs, &sfthd_node, policy_id);
}


int sfthd_test_rule(XHash* rule_hash, THD_NODE* sfthd_node,
    const SfIp* sip, const SfIp* dip, long curtime, PolicyId policy_id)
{
    if ( rule_hash == nullptr or sfthd_node == nullptr )
        return 0;

    int status = sfthd_test_local(rule_hash, sfthd_node, sip, dip, curtime, policy_id);
    return (status < -1) ? 1 : status;
}

static inline int sfthd_test_suppress(
    THD_NODE* sfthd_node,
    const SfIp* ip)
{
    if ( !sfthd_node->ip_address or
        sfvar_ip_in(sfthd_node->ip_address, ip) )
    {
        /* Don't log, and stop looking( event's to this address
         * for this gen_id+sig_id) */
        return -1;
    }
    return 1; /* Keep looking for other suppressors */
}

/*
 *  Do the appropriate test for the Threshold Object Type
 */
static inline int sfthd_test_non_suppress(
    THD_NODE* sfthd_node,
    THD_IP_NODE* sfthd_ip_node,
    time_t curtime)
{
    unsigned dt;

    if ( sfthd_node->type == THD_TYPE_DETECT )
    {
        dt = (unsigned)(curtime - sfthd_ip_node->tstart);

        if ( dt >= sfthd_node->seconds )
        {   /* reset */
            sfthd_ip_node->tstart = curtime;
            if ( (unsigned)(curtime - sfthd_ip_node->tlast) > sfthd_node->seconds )
                sfthd_ip_node->prev = 0;
            else
                sfthd_ip_node->prev = sfthd_ip_node->count - 1;
            sfthd_ip_node->count = 1;
        }
        sfthd_ip_node->tlast = curtime;

        if ( (int)sfthd_ip_node->count > sfthd_node->count or
            (int)sfthd_ip_node->prev > sfthd_node->count )
        {
            return 0; /* Log it, stop looking: log all > 'count' events */
        }

        /* Don't Log yet, don't keep looking:
         * already logged our limit, don't log this sid  */
        return -2;
    }
    if ( sfthd_node->type == THD_TYPE_LIMIT )
    {
        dt = (unsigned)(curtime - sfthd_ip_node->tstart);

        if ( dt >= sfthd_node->seconds )
        {   /* reset */
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;
        }

        if ( (int)sfthd_ip_node->count <= sfthd_node->count )
        {
            return 0; /* Log it, stop looking: only log the 1st 'count' events */
        }

        /* Don't Log yet, don't keep looking:
         * already logged our limit, don't log this sid  */
        return -2;
    }
    else if ( sfthd_node->type == THD_TYPE_THRESHOLD )
    {
        dt = (unsigned)(curtime - sfthd_ip_node->tstart);
        if ( dt >= sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;
        }
        if ( (int)sfthd_ip_node->count >= sfthd_node->count )
        {
            /* reset */
            sfthd_ip_node->count = 0;
            sfthd_ip_node->tstart= curtime;
            return 0; /* Log it, stop looking */
        }
        return -2; /* don't log yet */
    }
    else if ( sfthd_node->type == THD_TYPE_BOTH )
    {
        dt = (unsigned)(curtime - sfthd_ip_node->tstart);
        if ( dt >= sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;

            /* Don't Log yet, keep looking:
             * only log after we reach count, which must be > '1' */
            return -2;
        }
        else
        {
            if ( (int)sfthd_ip_node->count >= sfthd_node->count )
            {
                if ( (int)sfthd_ip_node->count >  sfthd_node->count )
                {
                    /* don't log it, stop looking:
                     * log once per time interval - than block it */
                    return -2;
                }
                /* Log it, stop looking:
                 * log the 1st event we see past 'count' events */
                return 0;
            }
            else  /* Block it from logging */
            {
                /* don't log it, stop looking:
                 * we must see at least count events 1st */
                return -2;
            }
        }
    }

    return 0;  /* should not get here, so log it just to be safe */
}

/*!
 *
 *  Find/Test/Add an event against a single threshold object.
 *  Events without thresholding objects are automatically loggable.
 *
 *  @param thd     Threshold table pointer
 *  @param sfthd_node Permanent Thresholding Object
 *  @param sip     Event/Packet Src IP address- should be host ordered for comparison
 *  @param dip     Event/Packet Dst IP address
 *  @param curtime Current Event/Packet time in seconds
 *
 *  @return  integer
 *  @retval   0 : Event is loggable
 *  @retval  >0 : Event should not be logged, try next thd object
 *  @retval  <0 : Event should never be logged to this user! Suppressed Event+IP
 *
 */
int sfthd_test_local(
    XHash* local_hash,
    THD_NODE* sfthd_node,
    const SfIp* sip,
    const SfIp* dip,
    time_t curtime,
    PolicyId policy_id)
{
    THD_IP_NODE_KEY key;
    THD_IP_NODE data,* sfthd_ip_node;
    const SfIp* ip;

    // -1 means don't do any limit or thresholding 
    if ( sfthd_node->count == THD_NO_THRESHOLD )
        return 0;

    // Get The correct IP
    if ( sfthd_node->tracking == THD_TRK_SRC )
        ip = sip;
    else
        ip = dip;

    // Check for and test Suppression of this event to this IP
    if ( sfthd_node->type == THD_TYPE_SUPPRESS )
        return sfthd_test_suppress(sfthd_node, ip);
    
    // Go on and do standard thresholding

    // Set up the key 
    key.policyId = policy_id;
    key.ip = *ip;
    key.thd_id = sfthd_node->thd_id;
    key.padding = 0;

    /* Set up a new data element */
    data.count  = 1;
    data.prev   = 0;
    data.tstart = data.tlast = curtime; /* Event time */

    // Check for any Permanent sig_id objects for this gen_id  or add this one ...
    
    std::lock_guard<std::mutex> lock(sfthd_hash_mutex);

    int status = local_hash->insert((void*)&key, &data);
    if (status == HASH_INTABLE)
    {
        /* Already in the table */
        sfthd_ip_node = (THD_IP_NODE*)local_hash->get_user_data();

        /* Increment the event count */
        sfthd_ip_node->count++;
    }
    else if (status == HASH_NOMEM)
    {
        event_filter_stats.xhash_nomem_peg_local++;
        return 1;
    }
    else if (status != HASH_OK)
    {
        /* hash error */
        return 1; /*  check the next threshold object */
    }
    else
    {
        /* Was not in the table - it was added - work with our copy of the data */
        sfthd_ip_node = &data;
    }

    return sfthd_test_non_suppress(sfthd_node, sfthd_ip_node, curtime);
}

/*
 *   Test a global thresholding object
 */
static inline int sfthd_test_global(
    XHash* global_hash,
    THD_NODE* sfthd_node,
    unsigned sig_id,     /* from current event */
    const SfIp* sip,        /* " */
    const SfIp* dip,        /* " */
    time_t curtime,
    PolicyId policy_id)
{
    THD_IP_GNODE_KEY key;
    THD_IP_NODE data;
    THD_IP_NODE* sfthd_ip_node;
    const SfIp* ip;

    /* -1 means don't do any limit or thresholding */
    if ( sfthd_node->count == THD_NO_THRESHOLD)
        return 0;
    
    /* Get The correct IP */
    if (sfthd_node->tracking == THD_TRK_SRC)
        ip = sip;
    else
        ip = dip;

    /* Check for and test Suppression of this event to this IP */
    if ( sfthd_node->type == THD_TYPE_SUPPRESS )
        return sfthd_test_suppress(sfthd_node, ip);
    
    /*
    *  Go on and do standard thresholding
    */

    /* Set up the key */
    key.ip = *ip;
    key.gen_id = sfthd_node->gen_id;
    key.sig_id = sig_id;
    key.policyId = policy_id;
    key.padding = 0;

    /* Set up a new data element */
    data.count  = 1;
    data.prev  = 0;
    data.tstart = data.tlast = curtime; /* Event time */

    /* Check for any Permanent sig_id objects for this gen_id  or add this one ...  */
    int status = global_hash->insert((void*)&key, &data);
    if ( status == HASH_INTABLE )
    {
        /* Already in the table */
        sfthd_ip_node = (THD_IP_NODE*)global_hash->get_user_data();

        /* Increment the event count */
        sfthd_ip_node->count++;
    }
    else if ( status == HASH_NOMEM )
    {
        event_filter_stats.xhash_nomem_peg_global++;
        return 1;
    }
    else if ( status != HASH_OK )
    {
        /* hash error */
        return 1; /*  check the next threshold object */
    }
    else
    {
        /* Was not in the table - it was added - work with our copy of the data */
        sfthd_ip_node = &data;
    }

    return sfthd_test_non_suppress(sfthd_node, sfthd_ip_node, curtime);
}

/*!
 *
 *  Test a an event against the threshold database.
 *  Events without thresholding objects are automatically
 *  loggable.
 *
 *  @param thd     Threshold table pointer
 *  @param gen_id  Generator Id from the event
 *  @param sig_id  Signature Id from the event
 *  @param sip     Event/Packet Src IP address
 *  @param dip     Event/Packet Dst IP address
 *  @param curtime Current Event/Packet time
 *
 *  @return  integer
 *  @retval  0 : Event is loggable
 *  @retval !0 : Event should not be logged (-1 suppressed, 1 filtered)
 *
 */
int sfthd_test_threshold(
    ThresholdObjects* thd_objs,
    THD_STRUCT* thd,
    unsigned gen_id,
    unsigned sig_id,
    const SfIp* sip,
    const SfIp* dip,
    long curtime,
    PolicyId policy_id)
{
    if ( thd_objs == nullptr or thd == nullptr or gen_id >= THD_MAX_GENID )
        return 0; // Invalid parameters or gen_id

    // Check if the gen_id exists in sfthd_vector
    if ( gen_id < thd_objs->sfthd_vector.size() )
    {
        GHash* sfthd_hash = thd_objs->sfthd_vector[gen_id];

        if ( sfthd_hash != nullptr )
        {
            tThdItemKey key = { policy_id, sig_id };
            THD_ITEM* sfthd_item = static_cast<THD_ITEM*>(sfthd_hash->find(&key));

            if ( sfthd_item != nullptr and sfthd_item->sfthd_node_list != nullptr )
            {
                SF_LNODE* cursor;
                for ( THD_NODE* sfthd_node = static_cast<THD_NODE*>(sflist_first(sfthd_item->sfthd_node_list, &cursor));
                     sfthd_node != nullptr;
                     sfthd_node = static_cast<THD_NODE*>(sflist_next(&cursor)) )
                {
                    int status = sfthd_test_local(thd->ip_nodes, sfthd_node, sip, dip, curtime, policy_id);
                    if ( status <= 0 )
                        return (status < -1) ? 1 : status;
                }
            }
        }
    }

    // Global threshold test
    if (policy_id < thd_objs->sfthd_gvector.size())
    {
        auto& g_thd_map = thd_objs->sfthd_gvector[policy_id];

        auto it = g_thd_map.find(gen_id);
        if ( gen_id != 0 and it == g_thd_map.end() )
            it = g_thd_map.find(0);

        if ( it != g_thd_map.end() )
        {
            THD_NODE* g_thd_node = it->second.get(); // Get the raw pointer from the unique_ptr
            if ( g_thd_node != nullptr )
            {
                int status = sfthd_test_global(thd->ip_gnodes, g_thd_node, sig_id, sip, dip, curtime, policy_id);
                if ( status <= 0 )
                    return (status < -1) ? 1 : status;
            }
        }
    }


    return 0; // Default to loggable if no blocking action is found
}


#ifdef THD_DEBUG

static char* printIP(unsigned u, char* buf, unsigned len)
{
    SnortSnprintf(buf, len, "%d.%d.%d.%d", (u>>24)&0xff, (u>>16)&0xff, (u>>8)&0xff, u&0xff);
    return s;
}
/*!
 *   A function to print the thresholding objects to stdout.
 *
 */
int sfthd_show_objects(ThresholdObjects* thd_objs)
{
    THD_ITEM* sfthd_item;
    THD_NODE* sfthd_node;
    unsigned gen_id;
    GHashNode* item_hash_node;

    for (gen_id=0; gen_id < THD_MAX_GENID; gen_id++ )
    {
        GHash* sfthd_hash = thd_objs->sfthd_array[gen_id];

        if ( !sfthd_hash )
            continue;

        printf("...GEN_ID = %u\n",gen_id);

        for (item_hash_node  = sfthd_hash->ghash_findfirst();
             item_hash_node != 0;
             item_hash_node  = sfthd_hash->ghash_findnext() )
        {
            /* Check for any Permanent sig_id objects for this gen_id */
            sfthd_item = (THD_ITEM*)item_hash_node->data;

            printf(".....GEN_ID = %u, SIG_ID = %u, Policy = %u\n",gen_id,sfthd_item->sig_id,
                sfthd_item->policyId);

            /* For each permanent thresholding object, test/add/update the thd object
               We maintain a list of thd objects for each gen_id+sig_id
               each object has it's own unique thd_id */
            SF_LNODE* cursor;

            for ( sfthd_node  = (THD_NODE*)sflist_first(sfthd_item->sfthd_node_list, &cursor);
                sfthd_node != 0;
                sfthd_node = (THD_NODE*)sflist_next(&cursor) )
            {
                printf(".........THD_ID  =%d\n",sfthd_node->thd_id);

                if ( sfthd_node->type == THD_TYPE_SUPPRESS )
                    printf(".........type    =Suppress\n");
                if ( sfthd_node->type == THD_TYPE_LIMIT )
                    printf(".........type    =Limit\n");
                if ( sfthd_node->type == THD_TYPE_THRESHOLD )
                    printf(".........type    =Threshold\n");
                if ( sfthd_node->type == THD_TYPE_BOTH )
                    printf(".........type    =Both\n");

                printf(".........tracking=%d\n",sfthd_node->tracking);
                printf(".........priority=%d\n",sfthd_node->priority);

                if ( sfthd_node->type == THD_TYPE_SUPPRESS )
                {
                    printf(".........ip      =%s\n",
                        sfthd_node->ip_address.ntoa());
                    printf(".........mask    =%d\n",
                        sfthd_node->ip_address.bits);
                    printf(".........not_flag=%d\n",sfthd_node->ip_mask);
                }
                else
                {
                    printf(".........count   =%d\n",sfthd_node->count);
                    printf(".........seconds =%u\n",sfthd_node->seconds);
                }
            }
        }
    }

    return 0;
}

#endif // THD_DEBUG
