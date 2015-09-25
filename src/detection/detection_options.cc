//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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
**  @file        detection_options.c
**  @author      Steven Sturges
**  @brief       Support functions for rule option tree
**
**  This implements tree processing for rule options, evaluating common
**  detection options only once per pattern match.
*/

#include "detection_options.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection_defines.h"
#include "detection_util.h"
#include "treenodes.h"
#include "fp_create.h"
#include "fp_detect.h"
#include "rules.h"

#include "time/ppm.h"
#include "time/profiler.h"
#include "utils/util.h"
#include "hash/sfxhash.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"
#include "ips_options/ips_byte_extract.h"
#include "ips_options/ips_flowbits.h"
#include "ips_options/ips_content.h"
#include "ips_options/ips_pcre.h"
#include "filters/detection_filter.h"
#include "main/thread.h"
#include "framework/ips_option.h"
#include "framework/cursor.h"
#include "managers/ips_manager.h"
#include "protocols/packet_manager.h"

typedef struct _detection_option_key
{
    option_type_t option_type;
    void* option_data;
} detection_option_key_t;

#define HASH_RULE_OPTIONS 16384
#define HASH_RULE_TREE 8192

uint32_t detection_option_hash_func(SFHASHFCN*, unsigned char* k, int)
{
    detection_option_key_t* key = (detection_option_key_t*)k;

    if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt = (IpsOption*)key->option_data;
        return opt->hash();
    }
    return 0;
}

int detection_option_key_compare_func(const void* k1, const void* k2, size_t)
{
    const detection_option_key_t* key1 = (detection_option_key_t*)k1;
    const detection_option_key_t* key2 = (detection_option_key_t*)k2;

#ifdef KEEP_THEM_ALLOCATED
    return DETECTION_OPTION_NOT_EQUAL;
#endif

    if (!key1 || !key2)
        return DETECTION_OPTION_NOT_EQUAL;

    if (key1->option_type != key2->option_type)
        return DETECTION_OPTION_NOT_EQUAL;

    if ( key1->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt1 = (IpsOption*)key1->option_data;
        IpsOption* opt2 = (IpsOption*)key2->option_data;

        if ( opt1 == opt2 )
            return DETECTION_OPTION_EQUAL;
    }
    return DETECTION_OPTION_NOT_EQUAL;
}

int detection_hash_free_func(void* option_key, void*)
{
    detection_option_key_t* key = (detection_option_key_t*)option_key;

    if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt = (IpsOption*)key->option_data;
        IpsManager::delete_option(opt);
    }
    return 0;
}

SFXHASH* DetectionHashTableNew(void)
{
    SFXHASH* doht = sfxhash_new(HASH_RULE_OPTIONS,
        sizeof(detection_option_key_t),
        0,                              /* Data size == 0, just store the ptr */
        0,                              /* Memcap */
        0,                              /* Auto node recovery */
        NULL,                           /* Auto free function */
        detection_hash_free_func,                           /* User free function */
        1);                             /* Recycle nodes */

    if (doht == NULL)
        FatalError("Failed to create rule detection option hash table");

    sfxhash_set_keyops(doht, detection_option_hash_func,
        detection_option_key_compare_func);

    return doht;
}

void DetectionHashTableFree(SFXHASH* doht)
{
    if (doht != NULL)
        sfxhash_delete(doht);
}

int add_detection_option(
    SnortConfig* sc, option_type_t type, void* option_data, void** existing_data)
{
    detection_option_key_t key;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config is NULL.\n",
            __FILE__, __LINE__);
    }

    if (sc->detection_option_hash_table == NULL)
        sc->detection_option_hash_table = DetectionHashTableNew();

    if (!option_data)
    {
        /* No option data, no conflict to resolve. */
        return DETECTION_OPTION_EQUAL;
    }

    key.option_type = type;
    key.option_data = option_data;

    *existing_data = sfxhash_find(sc->detection_option_hash_table, &key);
    if (*existing_data)
    {
        return DETECTION_OPTION_EQUAL;
    }

    sfxhash_add(sc->detection_option_hash_table, &key, option_data);
    return DETECTION_OPTION_NOT_EQUAL;
}

uint32_t detection_option_tree_hash(detection_option_tree_node_t* node)
{
    uint32_t a,b,c;
    int i;

    if (!node)
        return 0;

    a = b = c = 0;

    for (i=0; i<node->num_children; i++)
    {
#if (defined(__ia64) || defined(__amd64) || defined(_LP64))
        {
            /* Cleanup warning because of cast from 64bit ptr to 32bit int
             * warning on 64bit OSs */
            uint64_t ptr; /* Addresses are 64bits */
            ptr = (uint64_t)node->children[i]->option_data;
            a += (ptr >> 32);
            b += (ptr & 0xFFFFFFFF);
        }
#else
        a += (uint32_t)node->children[i]->option_data;
        b += 0;
#endif
        c += detection_option_tree_hash(node->children[i]);
        mix(a,b,c);
        a += node->children[i]->num_children;
        mix(a,b,c);
#if 0
        a += (uint32_t)node->children[i]->option_data;
        /* Recurse & hash up this guy's children */
        b += detection_option_tree_hash(node->children[i]);
        c += node->children[i]->num_children;
        mix(a,b,c);
#endif
    }

    final(a,b,c);

    return c;
}

uint32_t detection_option_tree_hash_func(SFHASHFCN*, unsigned char* k, int)
{
    detection_option_key_t* key = (detection_option_key_t*)k;
    detection_option_tree_node_t* node;

    if (!key || !key->option_data)
        return 0;

    node = (detection_option_tree_node_t*)key->option_data;

    return detection_option_tree_hash(node);
}

int detection_option_tree_compare(detection_option_tree_node_t* r, detection_option_tree_node_t* l)
{
    int ret = DETECTION_OPTION_NOT_EQUAL;
    int i;

    if ((r == NULL) && (l == NULL))
        return DETECTION_OPTION_EQUAL;

    if ((!r && l) || (r && !l))
        return DETECTION_OPTION_NOT_EQUAL;

    if (r->option_data != l->option_data)
        return DETECTION_OPTION_NOT_EQUAL;

    if (r->num_children != l->num_children)
        return DETECTION_OPTION_NOT_EQUAL;

    for (i=0; i<r->num_children; i++)
    {
        /* Recurse & check the children for equality */
        ret = detection_option_tree_compare(r->children[i], l->children[i]);
        if (ret != DETECTION_OPTION_EQUAL)
            return ret;
    }

    return DETECTION_OPTION_EQUAL;
}

int detection_option_tree_compare_func(const void* k1, const void* k2, size_t)
{
    detection_option_key_t* key_r = (detection_option_key_t*)k1;
    detection_option_key_t* key_l = (detection_option_key_t*)k2;
    detection_option_tree_node_t* r;
    detection_option_tree_node_t* l;

    if (!key_r || !key_l)
        return DETECTION_OPTION_NOT_EQUAL;

    r = (detection_option_tree_node_t*)key_r->option_data;
    l = (detection_option_tree_node_t*)key_l->option_data;

    return detection_option_tree_compare(r, l);
}

int detection_option_tree_free_func(void*, void* data)
{
    detection_option_tree_node_t* node = (detection_option_tree_node_t*)data;
    free_detection_option_tree(node);
    return 0;
}

void DetectionTreeHashTableFree(SFXHASH* dtht)
{
    if (dtht != NULL)
        sfxhash_delete(dtht);
}

SFXHASH* DetectionTreeHashTableNew(void)
{
    SFXHASH* dtht = sfxhash_new(
        HASH_RULE_TREE,
        sizeof(detection_option_key_t),
        0,      /* Data size == 0, just store the ptr */
        0,      /* Memcap */
        0,      /* Auto node recovery */
        NULL,   /* Auto free function */
        detection_option_tree_free_func,   /* User free function */
        1);     /* Recycle nodes */

    if (dtht == NULL)
        FatalError("Failed to create rule detection option hash table");

    sfxhash_set_keyops(
        dtht, detection_option_tree_hash_func,
        detection_option_tree_compare_func);

    return dtht;
}

#ifdef DEBUG_OPTION_TREE
static const char* const option_type_str[] =
{
    "RULE_OPTION_TYPE_LEAF_NODE",
    "RULE_OPTION_TYPE_CONTENT",
    "RULE_OPTION_TYPE_FLOWBIT",
    "RULE_OPTION_TYPE_IP_PROTO",
    "RULE_OPTION_TYPE_PCRE",
    "RULE_OPTION_TYPE_OTHER"
};

void print_option_tree(detection_option_tree_node_t* node, int level)
{
    int i;
    unsigned int indent = 12 - (11 - level) + strlen(option_type_str[node->option_type]);
    unsigned int offset = 0;
    if (level >= 10)
        offset++;

    DEBUG_WRAP(
        DebugFormat(DEBUG_DETECT, "%d%*s%*d 0x%x\n",
            level, indent - offset, option_type_str[node->option_type],
            54 - indent, node->num_children, node->option_data);

        for (i=0; i<node->num_children; i++)
            print_option_tree(node->children[i], level+1);
        );
}

#endif

int add_detection_option_tree(
    SnortConfig* sc, detection_option_tree_node_t* option_tree, void** existing_data)
{
    detection_option_key_t key;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
            __FILE__, __LINE__);
    }

    if (sc->detection_option_tree_hash_table == NULL)
        sc->detection_option_tree_hash_table = DetectionTreeHashTableNew();

    if (!option_tree)
    {
        /* No option data, no conflict to resolve. */
        return DETECTION_OPTION_EQUAL;
    }

    key.option_data = (void*)option_tree;
    key.option_type = RULE_OPTION_TYPE_LEAF_NODE;

    *existing_data = sfxhash_find(sc->detection_option_tree_hash_table, &key);
    if (*existing_data)
    {
        return DETECTION_OPTION_EQUAL;
    }

    sfxhash_add(sc->detection_option_tree_hash_table, &key, option_tree);
    return DETECTION_OPTION_NOT_EQUAL;
}

int detection_option_node_evaluate(
    detection_option_tree_node_t* node, detection_option_eval_data_t* eval_data,
    Cursor& orig_cursor)
{
    int i, result = 0;
    int rval = DETECTION_OPTION_NO_MATCH;
    char tmp_noalert_flag = 0;
    Cursor cursor = orig_cursor;
    char continue_loop = 1;
    char flowbits_setoperation = 0;
    int loop_count = 0;
    uint32_t tmp_byte_extract_vars[NUM_BYTE_EXTRACT_VARS];
    uint64_t cur_eval_pkt_count =
        (rule_eval_pkt_count + (PacketManager::get_rebuilt_packet_count()));
    NODE_PROFILE_VARS;

    // FIXIT-P these are initialized only to silence -O2 warnings
    // they are set before use below
    PatternMatchData* content_data = nullptr;
    PcreData* pcre_data = nullptr;

    if (!node || !eval_data || !eval_data->p || !eval_data->pomd)
        return 0;

    dot_node_state_t* state = node->state + get_instance_id();

    /* see if evaluated it before ... */
    if (node->is_relative == 0)
    {
        /* Only matters if not relative... */
        if ((state->last_check.ts.tv_usec == eval_data->p->pkth->ts.tv_usec) &&
            (state->last_check.ts.tv_sec == eval_data->p->pkth->ts.tv_sec) &&
            (state->last_check.packet_number == cur_eval_pkt_count) &&
            (state->last_check.rebuild_flag == (eval_data->p->packet_flags &
            PKT_REBUILT_STREAM)) &&
            (!(eval_data->p->packet_flags & PKT_ALLOW_MULTIPLE_DETECT)))
        {
            /* eval'd this rule option before on this packet,
             * use the cached result. */
            if ((state->last_check.flowbit_failed == 0) &&
                !(eval_data->p->packet_flags & PKT_IP_RULE_2ND) &&
                !(eval_data->p->proto_bits & (PROTO_BIT__TEREDO | PROTO_BIT__GTP )))
            {
                return state->last_check.result;
            }
        }
    }

    NODE_PROFILE_START(node);

    state->last_check.ts.tv_sec = eval_data->p->pkth->ts.tv_sec;
    state->last_check.ts.tv_usec = eval_data->p->pkth->ts.tv_usec;
    state->last_check.packet_number = cur_eval_pkt_count;
    state->last_check.rebuild_flag = (eval_data->p->packet_flags & PKT_REBUILT_STREAM);
    state->last_check.flowbit_failed = 0;

    /* Save some stuff off for repeated pattern tests */
    if ( node->option_type == RULE_OPTION_TYPE_CONTENT )
    {
        content_data = content_get_data(node->option_data);
    }
    else if (node->option_type == RULE_OPTION_TYPE_PCRE)
    {
        pcre_data = pcre_get_data(node->option_data);
    }

    /* No, haven't evaluated this one before... Check it. */
    do
    {
        switch (node->option_type)
        {
        case RULE_OPTION_TYPE_LEAF_NODE:
            /* Add the match for this otn to the queue. */
        {
            OptTreeNode* otn = (OptTreeNode*)node->option_data;
            PatternMatchData* pmd = (PatternMatchData*)eval_data->pmd;

            int pattern_size = 0;
            int check_ports = 1;
            int eval_rtn_result;
            unsigned int svc_idx;
            int16_t app_proto = eval_data->p->get_application_protocol();

            if (pmd)
                pattern_size = pmd->pattern_size;

            if ( app_proto and ((OTNX_MATCH_DATA*)(eval_data->pomd))->check_ports != 2 )
            {
                for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
                {
                    if ( app_proto == otn->sigInfo.services[svc_idx].service_ordinal )
                    {
                        check_ports = 0;
                        break;  /* out of for */
                    }
                }

                if (otn->sigInfo.num_services && check_ports)
                {
                    /* none of the services match */
                    DebugFormat(DEBUG_DETECT,
                        "[**] SID %d not matched because of service mismatch (%d!=%d [**]\n",
                        otn->sigInfo.id, app_proto, otn->sigInfo.services[0].service_ordinal);
                    break;  /* out of case */
                }
            }
            // Don't include RTN time
            NODE_PROFILE_TMPEND(node);
            eval_rtn_result = fpEvalRTN(getRuntimeRtnFromOtn(otn), eval_data->p, check_ports);
            NODE_PROFILE_TMPSTART(node);

            if (eval_rtn_result)
            {
                if ( !otn->detection_filter ||
                    !detection_filter_test(
                    otn->detection_filter,
                    eval_data->p->ptrs.ip_api.get_src(), eval_data->p->ptrs.ip_api.get_dst(),
                    eval_data->p->pkth->ts.tv_sec) )
                {
#ifdef PERF_PROFILING
                    if (PROFILING_RULES)
                        otn->state[get_instance_id()].matches++;
#endif
                    if (!eval_data->flowbit_noalert)
                    {
                        fpAddMatch((OTNX_MATCH_DATA*)eval_data->pomd, pattern_size, otn);
                    }
                    result = rval = DETECTION_OPTION_MATCH;
                }
            }
        }
        break;
        case RULE_OPTION_TYPE_CONTENT:
            if (node->evaluate)
            {
                /* This will be set in the fast pattern matcher if we found
                 * a content and the rule option specifies not that
                 * content. Essentially we've already evaluated this rule
                 * option via the content option processing since only not
                 * contents that are not relative in any way will have this
                 * flag set */
                if (content_data->last_check)
                {
                    PmdLastCheck* last_check =
                        content_data->last_check + get_instance_id();

                    if ((last_check->ts.tv_sec == eval_data->p->pkth->ts.tv_sec) &&
                        (last_check->ts.tv_usec == eval_data->p->pkth->ts.tv_usec) &&
                        (last_check->packet_number == cur_eval_pkt_count) &&
                        (last_check->rebuild_flag == (eval_data->p->packet_flags &
                        PKT_REBUILT_STREAM)))
                    {
                        rval = DETECTION_OPTION_NO_MATCH;
                        break;
                    }
                }
                rval = node->evaluate(node->option_data, cursor, eval_data->p);
            }
            break;
        case RULE_OPTION_TYPE_PCRE:
            if (node->evaluate)
            {
                rval = node->evaluate(node->option_data, cursor, eval_data->p);
            }
            break;
        case RULE_OPTION_TYPE_FLOWBIT:
            if (node->evaluate)
            {
                flowbits_setoperation = FlowBits_SetOperation(node->option_data);
                if (!flowbits_setoperation)
                {
                    rval = node->evaluate(node->option_data, cursor, eval_data->p);
                }
                else
                {
                    /* set to match so we don't bail early.  */
                    rval = DETECTION_OPTION_MATCH;
                }
            }
            break;
        default:
            if (node->evaluate)
                rval = node->evaluate(node->option_data, cursor, eval_data->p);
            break;
        }

        if (rval == DETECTION_OPTION_NO_MATCH)
        {
            state->last_check.result = result;
            NODE_PROFILE_END_NOMATCH(node);
            return result;
        }
        else if (rval == DETECTION_OPTION_FAILED_BIT)
        {
            eval_data->flowbit_failed = 1;
            /* clear the timestamp so failed flowbit gets eval'd again */
            state->last_check.flowbit_failed = 1;
            state->last_check.result = result;
            NODE_PROFILE_END_NOMATCH(node);
            return 0;
        }
        else if (rval == DETECTION_OPTION_NO_ALERT)
        {
            /* Cache the current flowbit_noalert flag, and set it
             * so nodes below this don't alert. */
            tmp_noalert_flag = eval_data->flowbit_noalert;
            eval_data->flowbit_noalert = 1;
        }

        /* Back up byte_extract vars so they don't get overwritten between rules */
        for (i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
        {
            GetByteExtractValue(&(tmp_byte_extract_vars[i]), (int8_t)i);
        }

#ifdef PPM_MGR
        if ( PPM_PKTS_ENABLED() )
        {
            PPM_GET_TIME();
            PPM_PACKET_TEST();
            if ( PPM_PACKET_ABORT_FLAG() )
            {
                /* bail if we exceeded time */
                if (result == DETECTION_OPTION_NO_MATCH)
                {
                    NODE_PROFILE_END_NOMATCH(node);
                }
                else
                {
                    NODE_PROFILE_END_MATCH(node);
                }
                state->last_check.result = result;
                return result;
            }
        }
#endif
        /* Don't include children's time in this node */
        NODE_PROFILE_TMPEND(node);

        /* Passed, check the children. */
        if (node->num_children)
        {
            for (i=0; i<node->num_children; i++)
            {
                int j = 0;
                detection_option_tree_node_t* child_node = node->children[i];
                dot_node_state_t* child_state = child_node->state + get_instance_id();

                for (j = 0; j < NUM_BYTE_EXTRACT_VARS; j++)
                {
                    SetByteExtractValue(tmp_byte_extract_vars[j], (int8_t)j);
                }

                if (loop_count > 0)
                {
                    if (child_state->result == DETECTION_OPTION_NO_MATCH)
                    {
                        if (((child_node->option_type == RULE_OPTION_TYPE_CONTENT)
                            || (child_node->option_type == RULE_OPTION_TYPE_PCRE))
                            && !child_node->is_relative)
                        {
                            /* If it's a non-relative content or pcre, no reason
                             * to check again.  Only increment result once.
                             * Should hit this condition on first loop iteration. */
                            if (loop_count == 1)
                                result++;
                            continue;
                        }
                        else if ((child_node->option_type == RULE_OPTION_TYPE_CONTENT)
                            && child_node->is_relative)
                        {
                            /* Check for an unbounded relative search.  If this
                             * failed before, it's going to fail again so don't
                             * go down this path again */
                            if ( is_unbounded(child_node->option_data) )
                            {
                                /* Only increment result once. Should hit this
                                 * condition on first loop iteration. */
                                if (loop_count == 1)
                                    result++;
                                continue;
                            }
                        }
                    }
                    else if (child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE)
                    {
                        /* Leaf node matched, don't eval again */
                        continue;
                    }
                    else if (child_state->result == child_node->num_children)
                    {
                        /* This branch of the tree matched or has options that
                         * don't need to be evaluated again, so don't need to
                         * evaluate this option again */
                        continue;
                    }
                }

                child_state->result = detection_option_node_evaluate(
                    node->children[i], eval_data, cursor);

                if (child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE)
                {
                    /* Leaf node won't have any children but will return success
                     * or failure */
                    result += child_state->result;
                }
                else if (child_state->result == child_node->num_children)
                {
                    /* Indicate that the child's tree branches are done */
                    result++;
                }
#ifdef PPM_MGR
                if ( PPM_PKTS_ENABLED() )
                {
                    PPM_GET_TIME();
                    PPM_PACKET_TEST();
                    if ( PPM_PACKET_ABORT_FLAG() )
                    {
                        /* bail if we exceeded time */
                        state->last_check.result = result;
                        return result;
                    }
                }
#endif
            }

            /* If all children branches matched, we don't need to reeval any of
             * the children so don't need to reeval this content/pcre rule
             * option at a new offset.
             * Else, reset the DOE ptr to last eval for offset/depth,
             * distance/within adjustments for this same content/pcre
             * rule option */
            if (result == node->num_children)
                continue_loop = 0;

            /* Don't need to reset since it's only checked after we've gone
             * through the loop at least once and the result will have
             * been set again already */
            //for (i = 0; i < node->num_children; i++)
            //    node->children[i]->result;
        }

        NODE_PROFILE_TMPSTART(node);

        if (rval == DETECTION_OPTION_NO_ALERT)
        {
            /* Reset the flowbit_noalert flag in eval data */
            eval_data->flowbit_noalert = tmp_noalert_flag;
        }

        if (continue_loop && (rval == DETECTION_OPTION_MATCH) && (node->relative_children))
        {
            if ( node->option_type == RULE_OPTION_TYPE_CONTENT )
            {
                continue_loop = content_next(content_data);
            }
            else if (node->option_type == RULE_OPTION_TYPE_PCRE)
            {
                continue_loop = pcre_next(pcre_data);
            }
            else
            {
                continue_loop = 0;
            }
        }
        else
        {
            continue_loop = 0;
        }

#ifdef PERF_PROFILING
        /* We're essentially checking this node again and it potentially
         * might match again */
        if (continue_loop && PROFILING_RULES)
            state->checks++;
#endif

        loop_count++;
    }
    while (continue_loop);

    if (flowbits_setoperation && (result == DETECTION_OPTION_MATCH))
    {
        /* Do any setting/clearing/resetting/toggling of flowbits here
         * given that other rule options matched. */
        rval = node->evaluate(node->option_data, cursor, eval_data->p);
        if (rval != DETECTION_OPTION_MATCH)
        {
            result = rval;
        }
    }

    if (eval_data->flowbit_failed)
    {
        /* something deeper in the tree failed a flowbit test, we may need to
         * reeval this node. */
        state->last_check.flowbit_failed = 1;
    }
    state->last_check.result = result;

    if (result == DETECTION_OPTION_NO_MATCH)
    {
        NODE_PROFILE_END_NOMATCH(node);
    }
    else
    {
        NODE_PROFILE_END_MATCH(node);
    }

    return result;
}

#ifdef PERF_PROFILING
typedef struct node_profile_stats
{
    uint64_t ticks;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
    uint64_t checks;
    uint64_t disables;
} node_profile_stats_t;

static void detection_option_node_update_otn_stats(
    detection_option_tree_node_t* node,
    node_profile_stats_t* stats, uint64_t checks
#ifdef PPM_MGR
    , uint64_t disables
#endif
    )
{
    int i;
    node_profile_stats_t local_stats; /* cumulative stats for this node */
    node_profile_stats_t node_stats;  /* sum of all instances */

    memset(&node_stats, 0, sizeof(node_stats));

    for ( unsigned i = 0; i < get_instance_max(); ++i )
    {
        node_stats.ticks += node->state[i].ticks;
        node_stats.ticks_match += node->state[i].ticks_match;
        node_stats.ticks_no_match += node->state[i].ticks_no_match;
        node_stats.checks += node->state[i].checks;
    }
    if (stats)
    {
        local_stats.ticks = stats->ticks + node_stats.ticks;
        local_stats.ticks_match = stats->ticks_match + node_stats.ticks_match;
        local_stats.ticks_no_match = stats->ticks_no_match + node_stats.ticks_no_match;
        if (node_stats.checks > stats->checks)
            local_stats.checks = node_stats.checks;
        else
            local_stats.checks = stats->checks;
#ifdef PPM_MGR
        local_stats.disables = disables;
#endif
    }
    else
    {
        local_stats.ticks = node_stats.ticks;
        local_stats.ticks_match = node_stats.ticks_match;
        local_stats.ticks_no_match = node_stats.ticks_no_match;
        local_stats.checks = node_stats.checks;
#ifdef PPM_MGR
        local_stats.disables = disables;
#endif
    }

    if (node->option_type == RULE_OPTION_TYPE_LEAF_NODE)
    {
        /* Update stats for this otn */
        // FIXIT-M should be sum of instances (only called from main thread)
        OptTreeNode* otn = (OptTreeNode*)node->option_data;
        OtnState* state = otn->state + get_instance_id();
        state->ticks += local_stats.ticks;
        state->ticks_match += local_stats.ticks_match;
        state->ticks_no_match += local_stats.ticks_no_match;
        if (local_stats.checks > state->checks)
            state->checks = local_stats.checks;
#ifdef PPM_MGR
        state->ppm_disable_cnt += local_stats.disables;
#endif
    }

    if (node->num_children)
    {
        for (i=0; i<node->num_children; i++)
        {
            detection_option_node_update_otn_stats(
                node->children[i], &local_stats, checks
#ifdef PPM_MGR
                , disables
#endif
                );
        }
    }
}

void detection_option_tree_update_otn_stats(SFXHASH* doth)
{
    if (doth == NULL)
        return;

    /* Find the first tree root in the table */
    SFXHASH_NODE* hashnode = sfxhash_findfirst(doth);

    while (hashnode)
    {
        detection_option_tree_node_t* node =
            (detection_option_tree_node_t*)hashnode->data;

        uint64_t checks = 0;
#ifdef PPM_MGR
        uint64_t disables = 0;
#endif

        for ( unsigned i = 0; i < get_instance_max(); ++i )
        {
            checks += node->state[i].checks;
#ifdef PPM_MGR
            disables += node->state[i].ppm_disable_cnt;
#endif
        }

        if ( checks )
        {
            detection_option_node_update_otn_stats(
                node, NULL, checks
#ifdef PPM_MGR
                , disables
#endif
                );
        }
        hashnode = sfxhash_findnext(doth);
    }
}

#endif

detection_option_tree_root_t* new_root()
{
    detection_option_tree_root_t* p = (detection_option_tree_root_t*)
        SnortAlloc(sizeof(detection_option_tree_root_t));

#ifdef PPM_MGR
    p->state = (dot_root_state_t*)
        SnortAlloc(sizeof(dot_root_state_t)*get_instance_max());
#endif

    return p;
}

void free_detection_option_root(void** existing_tree)
{
    detection_option_tree_root_t* root;

    if (!existing_tree || !*existing_tree)
        return;

    root = (detection_option_tree_root_t*)*existing_tree;
    free(root->children);
#ifdef PPM_MGR
    free(root->state);
#endif
    free(root);
    *existing_tree = NULL;
}

detection_option_tree_node_t* new_node(
    option_type_t type, void* data)
{
    detection_option_tree_node_t* p =
        (detection_option_tree_node_t*)SnortAlloc(sizeof(*p));

    p->option_type = type;
    p->option_data = data;

    p->state = (dot_node_state_t*)
        SnortAlloc(sizeof(*p->state) * get_instance_max());

    return p;
}

void free_detection_option_tree(detection_option_tree_node_t* node)
{
    int i;
    for (i=0; i<node->num_children; i++)
    {
        free_detection_option_tree(node->children[i]);
    }
    free(node->children);
    free(node->state);
    free(node);
}

