//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
**
**  NOTES
**  5.7.02 - Initial Checkin. Norton/Roelker
**
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fp_create.h"

#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "hash/ghash.h"
#include "hash/hash_defs.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/mpse_manager.h"
#include "parser/parse_rule.h"
#include "parser/parser.h"
#include "ports/port_table.h"
#include "ports/rule_port_tables.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "detection_options.h"
#include "detect_trace.h"
#include "fp_config.h"
#include "fp_utils.h"
#include "pattern_match_data.h"
#include "pcrm.h"
#include "service_map.h"
#include "treenodes.h"

using namespace snort;
using namespace std;

static unsigned mpse_count = 0;
static unsigned offload_mpse_count = 0;
static unsigned fp_only = 0;
static const char* s_group = "";

static void fpDeletePMX(void* data);

static int fpGetFinalPattern(
    FastPatternConfig*, PatternMatchData*, const char*& ret_pattern, unsigned& ret_bytes);

static void print_nfp_info(const char*, OptTreeNode*);
static void print_fp_info(const char*, const OptTreeNode*, const PatternMatchData*);

static OptTreeNode* fixup_tree(
    detection_option_tree_node_t* dot, bool branched, unsigned contents)
{
    if ( dot->num_children == 0 )
    {
        if ( !branched and contents )
            return (OptTreeNode*)dot->option_data;

        dot->otn = (OptTreeNode*)dot->option_data;
        return nullptr;
    }
    if ( dot->num_children == 1 )
    {
        if ( dot->option_type == RULE_OPTION_TYPE_CONTENT )
            ++contents;

        OptTreeNode* otn = fixup_tree(dot->children[0], false, contents);

        if ( !branched and contents > 1 )
            return otn;

        dot->otn = otn;
        return nullptr;
    }
    for ( int i = 0; i < dot->num_children; ++i )
        fixup_tree(dot->children[i], true, 0);

    return nullptr;
}

static int finalize_detection_option_tree(SnortConfig* sc, detection_option_tree_root_t* root)
{
    if ( !root )
        return -1;

    for ( int i=0; i<root->num_children; i++ )
    {
        detection_option_tree_node_t* node = root->children[i];

        if ( void* dup_node = add_detection_option_tree(sc, node) )
        {
            // FIXIT-L delete dup_node and keep original?
            free_detection_option_tree(node);
            root->children[i] = (detection_option_tree_node_t*)dup_node;
        }
        fixup_tree(root->children[i], true, 0);

        debug_logf(detection_trace, TRACE_OPTION_TREE, nullptr, "%3d %3d  %p %4s\n",
            0, root->num_children, (void*)root, "root" );

        print_option_tree(root->children[i], 0);
    }

    return 0;
}

static bool new_sig(int num_children, detection_option_tree_node_t** nodes, OptTreeNode* otn)
{
    for ( int i = 0; i < num_children; ++i )
    {
        detection_option_tree_node_t* child = nodes[i];

        if ( child->option_type != RULE_OPTION_TYPE_LEAF_NODE )
            continue;

        OptTreeNode* cotn = (OptTreeNode*)child->option_data;
        SigInfo& csi = cotn->sigInfo;
        SigInfo& osi = otn->sigInfo;

        if ( csi.gid == osi.gid and csi.sid == osi.sid and csi.rev == osi.rev )
            return false;
    }
    return true;
}

static int otn_create_tree(OptTreeNode* otn, void** existing_tree, Mpse::MpseType mpse_type)
{
    detection_option_tree_node_t* node = nullptr, * child;
    bool need_leaf = false;

    if (!existing_tree)
        return -1;

    if (!*existing_tree)
        *existing_tree = new_root(otn);

    detection_option_tree_root_t* root = (detection_option_tree_root_t*)*existing_tree;

    if (!root->children)
    {
        root->num_children++;
        root->children = (detection_option_tree_node_t**)
            snort_calloc(root->num_children, sizeof(detection_option_tree_node_t*));
        need_leaf = true;
    }

    int i = 0;
    child = root->children[i];
    OptFpList* opt_fp = otn->opt_func;

    /* Build out sub-nodes for each option in the OTN fp list */
    while (opt_fp)
    {
        /* If child node does not match existing option_data,
         * Create a child branch from a given sub-node. */
        void* option_data = opt_fp->ips_opt;

        if (opt_fp->type == RULE_OPTION_TYPE_LEAF_NODE)
        {
            opt_fp = opt_fp->next;
            continue;
        }

        /* Don't add contents that are only for use in the
         * fast pattern matcher */
        if ( is_fast_pattern_only(otn, opt_fp, mpse_type) )
        {
            opt_fp = opt_fp->next;
            continue;
        }

        if (!child)
        {
            /* No children at this node */
            child = new_node(opt_fp->type, option_data);
            child->evaluate = opt_fp->OptTestFunc;

            if (!node)
                root->children[i] = child;
            else
                node->children[i] = child;

            child->num_children++;
            child->children = (detection_option_tree_node_t**)
                snort_calloc(child->num_children, sizeof(detection_option_tree_node_t*));
            child->is_relative = opt_fp->isRelative;

            if (node && child->is_relative)
                node->relative_children++;

            need_leaf = true;
        }
        else
        {
            bool found_child_match = false;

            if (child->option_data != option_data)
            {
                if (!node)
                {
                    for (i=1; i<root->num_children; i++)
                    {
                        child = root->children[i];
                        if (child->option_data == option_data)
                        {
                            found_child_match = true;
                            break;
                        }
                    }
                }
                else
                {
                    for (i=1; i<node->num_children; i++)
                    {
                        child = node->children[i];
                        if (child->option_data == option_data)
                        {
                            found_child_match = true;
                            break;
                        }
                    }
                }
            }
            else
            {
                found_child_match = true;
            }

            if ( !found_child_match )
            {
                /* No matching child node, create a new and add to array */
                detection_option_tree_node_t** tmp_children;
                child = new_node(opt_fp->type, option_data);
                child->evaluate = opt_fp->OptTestFunc;
                child->num_children++;
                child->children = (detection_option_tree_node_t**)
                    snort_calloc(child->num_children, sizeof(child->children));
                child->is_relative = opt_fp->isRelative;

                if (!node)
                {
                    root->num_children++;
                    tmp_children = (detection_option_tree_node_t**)
                        snort_calloc(root->num_children, sizeof(tmp_children));
                    memcpy(tmp_children, root->children,
                        sizeof(detection_option_tree_node_t*) * (root->num_children-1));

                    snort_free(root->children);
                    root->children = tmp_children;
                    root->children[root->num_children-1] = child;
                }
                else
                {
                    node->num_children++;
                    tmp_children = (detection_option_tree_node_t**)
                        snort_calloc(node->num_children, sizeof(detection_option_tree_node_t*));
                    memcpy(tmp_children, node->children,
                        sizeof(detection_option_tree_node_t*) * (node->num_children-1));

                    snort_free(node->children);
                    node->children = tmp_children;
                    node->children[node->num_children-1] = child;
                    if (child->is_relative)
                        node->relative_children++;
                }
                need_leaf = true;
            }
        }
        node = child;
        i=0;
        child = node->children[i];
        opt_fp = opt_fp->next;
    }

    // don't add a new leaf node unless we branched higher in the tree or this
    // is a different sig ( eg alert ip ( sid:1; ) vs alert tcp ( sid:2; ) )
    // note: same sig different policy branches at rtn (this is for same policy)

    if ( !need_leaf )
    {
        if ( node )
            need_leaf = new_sig(node->num_children, node->children, otn);
        else
            need_leaf = new_sig(root->num_children, root->children, otn);
    }

    if ( !need_leaf )
        return 0;

    /* Append a leaf node that has option data of the SigInfo/otn pointer */
    child = new_node(RULE_OPTION_TYPE_LEAF_NODE, otn);

    if (!node)
    {
        if (root->children[0])
        {
            detection_option_tree_node_t** tmp_children;
            root->num_children++;
            tmp_children = (detection_option_tree_node_t**)
                snort_calloc(root->num_children, sizeof(detection_option_tree_node_t*));
            memcpy(tmp_children, root->children,
                sizeof(detection_option_tree_node_t*) * (root->num_children-1));
            snort_free(root->children);
            root->children = tmp_children;
        }
        root->children[root->num_children-1] = child;
    }
    else
    {
        if (node->children[0])
        {
            detection_option_tree_node_t** tmp_children;
            node->num_children++;
            tmp_children = (detection_option_tree_node_t**)
                snort_calloc(node->num_children, sizeof(detection_option_tree_node_t*));
            memcpy(tmp_children, node->children,
                sizeof(detection_option_tree_node_t*) * (node->num_children-1));
            snort_free(node->children);
            node->children = tmp_children;
        }
        node->children[node->num_children-1] = child;
    }

    return 0;
}

static int add_patrn_to_neg_list(void* id, void** list)
{
    if ( !id or !list )
        return -1;

    NCListNode** ncl = (NCListNode**)list;
    NCListNode* node = (NCListNode*)snort_alloc(sizeof(NCListNode));

    node->pmx = (PMX*)id;
    node->next = *ncl;
    *ncl = node;

    return 0;
}

static void neg_list_free(void** list)
{
    NCListNode* ncln;

    if (list == nullptr)
        return;

    ncln = (NCListNode*)*list;
    while (ncln != nullptr)
    {
        NCListNode* tmp = ncln->next;
        snort_free(ncln);
        ncln = tmp;
    }

    *list = nullptr;
}

static int pmx_create_tree(SnortConfig* sc, void* id, void** existing_tree, Mpse::MpseType mpse_type)
{
    assert(existing_tree);

    if (!id)
    {
        if ( !*existing_tree )
            return -1;

        /* null input id (PMX *), last call for this pattern state */
        return finalize_detection_option_tree(sc, (detection_option_tree_root_t*)*existing_tree);
    }

    PMX* pmx = (PMX*)id;
    OptTreeNode* otn = (OptTreeNode*)pmx->rule_node.rnRuleData;

    if (!*existing_tree)
        *existing_tree = new_root(otn);

    return otn_create_tree(otn, existing_tree, mpse_type);
}

static int pmx_create_tree_normal(SnortConfig* sc, void* id, void** existing_tree)
{
    return pmx_create_tree(sc, id, existing_tree, Mpse::MPSE_TYPE_NORMAL);
}

static int pmx_create_tree_offload(SnortConfig* sc, void* id, void** existing_tree)
{
    return pmx_create_tree(sc, id, existing_tree, Mpse::MPSE_TYPE_OFFLOAD);
}

static int fpFinishRuleGroupRule(
    Mpse* mpse, OptTreeNode* otn, PatternMatchData* pmd, FastPatternConfig* fp, bool get_final_pat)
{
    const char* pattern;
    unsigned pattern_length;

    if (get_final_pat)
    {
        if (fpGetFinalPattern(fp, pmd, pattern, pattern_length) == -1)
            return -1;
    }
    else
    {
        pattern = pmd->pattern_buf;
        pattern_length = pmd->pattern_size;
    }

    if (pmd->pattern_size > otn->longestPatternLen)
        otn->longestPatternLen = pmd->pattern_size;

    PMX* pmx = (PMX*)snort_calloc(sizeof(PMX));
    pmx->rule_node.rnRuleData = otn;
    pmx->pmd = pmd;

    Mpse::PatternDescriptor desc(
        pmd->is_no_case(), pmd->is_negated(), pmd->is_literal(), false, pmd->mpse_flags);

    mpse->add_pattern((const uint8_t*)pattern, pattern_length, desc, pmx);

    return 0;
}

static int fpFinishRuleGroup(SnortConfig* sc, RuleGroup* pg)
{
    assert(pg);
    bool has_rules = false;

    for ( auto& it : pg->pm_list )
    {
        if ( it->group.normal_mpse )
        {
            queue_mpse(it->group.normal_mpse);
            has_rules = true;
        }
        if ( it->group.offload_mpse )
        {
            queue_mpse(it->group.offload_mpse);
            has_rules = true;
        }
    }

    if ( pg->nfp_head )
    {
        RULE_NODE* ruleNode;

        for ( ruleNode = pg->nfp_head; ruleNode; ruleNode = ruleNode->rnNext )
        {
            OptTreeNode* otn = (OptTreeNode*)ruleNode->rnRuleData;
            otn_create_tree(otn, &pg->nfp_tree, Mpse::MPSE_TYPE_NORMAL);
        }

        finalize_detection_option_tree(sc, (detection_option_tree_root_t*)pg->nfp_tree);
        has_rules = true;

        pg->delete_nfp_rules();
    }

    if ( !has_rules )
    {
        delete pg;
        return -1;
    }

    return 0;
}

static int fpAddRuleGroupRule(
    SnortConfig* sc, RuleGroup* pg, OptTreeNode* otn, FastPatternConfig* fp, bool srvc)
{
    const MpseApi* search_api = nullptr;
    const MpseApi* offload_search_api = nullptr;
    bool exclude;

    // skip builtin rules, continue for text and so rules
    if ( otn->sigInfo.builtin )
        return -1;

    if ( !otn->enabled_somewhere() )
        return -1;

    search_api = fp->get_search_api();
    assert(search_api);

    OptFpList* ofp = nullptr;
    IpsOption* opt = nullptr;

    bool only_literal = !MpseManager::is_regex_capable(search_api);
    PatternMatchVector pmv = get_fp_content(otn, ofp, opt, srvc, only_literal, exclude);

    if ( !pmv.empty() )
    {
        PatternMatchVector pmv_ol;
        OptFpList* ofp_ol = nullptr;
        IpsOption* opt_ol = nullptr;
        bool add_to_offload = false;
        bool cont = true;
        PatternMatchData* ol_pmd = nullptr;

        offload_search_api = fp->get_offload_search_api();

        // Only add rule to the offload search engine if the offload search engine
        // is different to the normal search engine.
        if ( offload_search_api and (offload_search_api != search_api) )
        {
            bool exclude_ol;
            bool only_literal_ol = !MpseManager::is_regex_capable(offload_search_api);
            pmv_ol = get_fp_content(otn, ofp_ol, opt_ol, srvc, only_literal_ol, exclude_ol);

            // If we can get a fast_pattern for the normal search engine but not for the
            // offload search engine then add rule to the non fast pattern list
            if ( !pmv_ol.empty() )
                add_to_offload = true;
            else
                cont = false;
        }

        // From here on we will create the mpses that are needed and add the patterns
        if ( cont )
        {
            PatternMatchData* main_pmd = pmv.back();
            pmv.pop_back();

            static MpseAgent agent =
            {
                pmx_create_tree_normal, add_patrn_to_neg_list,
                fpDeletePMX, free_detection_option_root, neg_list_free
            };

            const char* s = opt ? opt->get_name() : "pkt_data";
            auto pmt = get_pm_type(s);
            PatternMatcher* pm = pg->get_pattern_matcher(pmt, s);
            MpseGroup* mpg = &pm->group;

            if ( !mpg->normal_mpse )
            {
                if ( !mpg->create_normal_mpse(sc, &agent) )
                {
                    ParseError("Failed to create normal pattern matcher for %s", pm->name);
                    return -1;
                }

                mpse_count++;
            }

            if ( add_to_offload )
            {
                ol_pmd = pmv_ol.back();
                pmv_ol.pop_back();

                static MpseAgent agent_offload =
                {
                    pmx_create_tree_offload, add_patrn_to_neg_list,
                    fpDeletePMX, free_detection_option_root, neg_list_free
                };

                // Keep the created mpse alongside the same pm type as the main pmd
                if ( !mpg->offload_mpse )
                {
                    if ( !mpg->create_offload_mpse(sc, &agent_offload) )
                    {
                        ParseError("Failed to create offload pattern matcher for %s", pm->name);
                        return -1;
                    }

                    offload_mpse_count++;
                }
            }

            bool add_rule = false;
            bool add_nfp_rule = false;

            if ( mpg->normal_mpse )
            {
                add_rule = true;
                if ( main_pmd->is_negated() )
                    add_nfp_rule = true;

                // Now add patterns
                if ( fpFinishRuleGroupRule(mpg->normal_mpse, otn, main_pmd, fp, true) == 0 )
                {
                    if ( make_fast_pattern_only(ofp, main_pmd) )
                    {
                        otn->normal_fp_only = ofp;
                        fp_only++;
                    }

                    if ( !pm->fp_opt )
                        pm->fp_opt = opt;

                    main_pmd->sticky_buf = pm->name;

                    if ( fp->get_debug_print_fast_patterns() and !otn->soid )
                        print_fp_info(s_group, otn, main_pmd);

                    // Add Alternative patterns
                    for ( auto alt_pmd : pmv )
                    {
                        fpFinishRuleGroupRule(mpg->normal_mpse, otn, alt_pmd, fp, false);
                        alt_pmd->sticky_buf = pm->name;

                        if ( fp->get_debug_print_fast_patterns() and !otn->soid )
                            print_fp_info(s_group, otn, alt_pmd);
                    }
                }
            }

            if ( ol_pmd and mpg->offload_mpse )
            {
                add_rule = true;
                if ( ol_pmd->is_negated() )
                    add_nfp_rule = true;

                // Now add patterns
                if ( fpFinishRuleGroupRule(mpg->offload_mpse, otn, ol_pmd, fp, true) == 0 )
                {
                    if ( make_fast_pattern_only(ofp_ol, ol_pmd) )
                    {
                        otn->offload_fp_only = ofp_ol;
                        fp_only++;
                    }

                    if ( !pm->fp_opt )
                        pm->fp_opt = opt_ol;

                    main_pmd->sticky_buf = pm->name;

                    if ( fp->get_debug_print_fast_patterns() and !otn->soid )
                        print_fp_info(s_group, otn, main_pmd);

                    // Add Alternative patterns
                    for (auto alt_pmd : pmv_ol)
                    {
                        fpFinishRuleGroupRule(mpg->offload_mpse, otn, alt_pmd, fp, false);
                        alt_pmd->sticky_buf = pm->name;

                        if ( fp->get_debug_print_fast_patterns() and !otn->soid )
                            print_fp_info(s_group, otn, alt_pmd);
                    }
                }
            }

            if ( add_rule )
            {
                if ( !add_nfp_rule )
                    pg->add_rule();
                else
                {
                    pg->add_nfp_rule(otn);
                    print_nfp_info(s_group, otn);
                }
            }
            return 0;
        }
    }

    if ( exclude )
        return 0;

    // no fast pattern added
    pg->add_nfp_rule(otn);
    print_nfp_info(s_group, otn);

    return 0;
}

/*
 * Original PortRuleMaps for each protocol requires creating the following structures.
 *
 * PORT_RULE_MAP -> srcRuleGroup,dstRuleGroup,genericRuleGroup
 * RuleGroup     -> pgPatData, pgPatDataUri (acsm objects), (also rule_node lists 1/rule,
 *                  not needed).  each rule content added to an acsm object has a PMX data ptr
 *                  associated with it.
 * RULE_NODE     -> iRuleNodeID (used for bitmap object index)
 * PMX           -> RULE_NODE(->otn), PatternMatchData
 *
 * PortList model supports the same structures except:
 *
 * RuleGroup    -> no rule_node lists needed, PortObjects maintain a list of rules used
 *
 * Generation of PortRuleMaps and data is done differently.
 *
 * 1) Build tcp/udp/icmp/ip src and dst RuleGroup objects based on the PortList Objects rules.
 *
 * 2) For each protocols PortList objects walk it's ports and assign the PORT_RULE_MAP src and
 *    dst RuleGroup[port] array pointers to that PortList objects RuleGroup.
 *
 * Implementation:
 *
 *    Each PortList Object will be translated into a RuleGroup, then pointed to by the
 *    RuleGroup array in the PORT_RULE_MAP for the protocol
 *
 *    protocol = tcp, udp, ip, icmp - one port_rule_map for each of these protocols
 *    { create a port_rule_map
 *      dst port processing
 *          for each port-list object create a port_group object
 *          {   create a pattern match object, store its pointer in port_group
 *              for each rule index in port-list object
 *              {
 *                  get the gid+sid for the index
 *                  lookup up the otn
 *                  create pmx
 *                  create RULE_NODE, set iRuleNodeID within this port-list object
 *                  get longest content for the rule
 *                  set up pmx,RULE_NODE
 *                  add the content and pmx to the pattern match object
 *              }
 *              compile the pattern match object
 *
 *              repeat for uri content
 *          }
 *      src port processing
 *          repeat as for dst port processing
 *    }
 *    ** bidirectional rules - these are added to both src and dst PortList objects, so they are
 *    automatically handled during conversion to port_group objects.
 */
/*
**  Build a Pattern group for the Uri-Content rules in this group
**
**  The patterns added for each rule must be sufficient so if we find any of them
**  we proceed to fully analyze the OTN and RTN against the packet.
**
*/
/*
 *  Init a port-list based rule map
 */
struct PortIteratorData
{
    PortIteratorData(RuleGroup** a, RuleGroup* g)
    {
        array = a;
        group = g;
    }

    static void set(int port, void* pv)
    {
        PortIteratorData* pid = (PortIteratorData*)pv;
        pid->array[port] = pid->group;
    }

    RuleGroup** array;
    RuleGroup* group;
};

static void fpCreateInitRuleMap(
    PORT_RULE_MAP* prm, PortTable* src, PortTable* dst, PortObject* any)
{
    /* setup the any-port content port group */
    prm->prmGeneric = any->group;

    /* all rules that are any any some may not be content ? */
    prm->prmNumGenericRules = any->rule_list->count;

    prm->prmNumSrcRules = 0;
    prm->prmNumDstRules = 0;

    prm->prmNumSrcGroups = 0;
    prm->prmNumDstGroups = 0;

    /* Process src PORT groups */
    if ( src )
    {
        for (GHashNode* node = src->pt_mpxo_hash->find_first();
             node;
             node = src->pt_mpxo_hash->find_next())
        {
            PortObject2* po = (PortObject2*)node->data;

            if ( !po or !po->group )
                continue;

            /* Add up the total src rules */
            prm->prmNumSrcRules  += po->rule_hash->get_count();

            /* Increment the port group count */
            prm->prmNumSrcGroups++;

            /* Add this port group to the src table at each port that uses it */
            PortIteratorData pit_data(prm->prmSrcPort, po->group);
            PortObject2Iterate(po, PortIteratorData::set, &pit_data);
        }
    }

    /* process destination port groups */
    if ( dst )
    {
        for (GHashNode* node = dst->pt_mpxo_hash->find_first();
             node;
             node = dst->pt_mpxo_hash->find_next())
        {
            PortObject2* po = (PortObject2*)node->data;

            if ( !po or !po->group )
                continue;

            /* Add up the total src rules */
            prm->prmNumDstRules  += po->rule_hash->get_count();

            /* Increment the port group count */
            prm->prmNumDstGroups++;

            /* Add this port group to the src table at each port that uses it */
            PortIteratorData pit_data(prm->prmDstPort, po->group);
            PortObject2Iterate(po, PortIteratorData::set, &pit_data);
        }
    }
}

/*
 * Create and initialize the rule maps
 */
static void fpCreateRuleMaps(SnortConfig* sc, RulePortTables* p)
{
    sc->prmIpRTNX = prmNewMap();
    sc->prmIcmpRTNX = prmNewMap();
    sc->prmTcpRTNX = prmNewMap();
    sc->prmUdpRTNX = prmNewMap();

    fpCreateInitRuleMap(sc->prmIpRTNX, p->ip.src, p->ip.dst, p->ip.any);
    fpCreateInitRuleMap(sc->prmIcmpRTNX, p->icmp.src, p->icmp.dst, p->icmp.any);
    fpCreateInitRuleMap(sc->prmTcpRTNX, p->tcp.src, p->tcp.dst, p->tcp.any);
    fpCreateInitRuleMap(sc->prmUdpRTNX, p->udp.src, p->udp.dst, p->udp.any);
}

static void fpFreeRuleMaps(SnortConfig* sc)
{
    if (sc == nullptr)
        return;

    if (sc->prmIpRTNX != nullptr)
    {
        snort_free(sc->prmIpRTNX);
        sc->prmIpRTNX = nullptr;
    }

    if (sc->prmIcmpRTNX != nullptr)
    {
        snort_free(sc->prmIcmpRTNX);
        sc->prmIcmpRTNX = nullptr;
    }

    if (sc->prmTcpRTNX != nullptr)
    {
        snort_free(sc->prmTcpRTNX);
        sc->prmTcpRTNX = nullptr;
    }

    if (sc->prmUdpRTNX != nullptr)
    {
        snort_free(sc->prmUdpRTNX);
        sc->prmUdpRTNX = nullptr;
    }
}

static int fpGetFinalPattern(
    FastPatternConfig* fp, PatternMatchData* pmd, const char*& ret_pattern, unsigned& ret_bytes)
{
    assert(fp and pmd);

    const char* pattern = pmd->pattern_buf;
    unsigned bytes = pmd->pattern_size;

    // Don't mess with:
    //
    // 1. fast pattern only contents - they should be inserted into the
    // pattern matcher as is since the content won't be evaluated as a rule
    // option.
    //
    // 2. negated contents since truncating them could inadvertently
    // disable evaluation of a rule - the shorter pattern may be found,
    // while the unaltered pattern may not be found, disabling inspection
    // of a rule we should inspect.
    //
    // 3. non-literals like regex - truncation could invalidate the
    // expression.

    if ( pmd->is_negated() or !pmd->is_literal() )
    {
        ret_pattern = pattern;
        ret_bytes = bytes;
        return 0;
    }

    if ( pmd->is_fast_pattern() && (pmd->fp_offset || pmd->fp_length) )
    {
        /* (offset + length) potentially being larger than the pattern itself
         * is taken care of during parsing */
        assert(pmd->fp_offset + pmd->fp_length <= pmd->pattern_size);
        pattern = pmd->pattern_buf + pmd->fp_offset;
        bytes = pmd->fp_length ? pmd->fp_length : pmd->pattern_size - pmd->fp_offset;
    }

    ret_pattern = pattern;
    ret_bytes = fp->set_max(bytes);

    if ( ret_bytes < pmd->pattern_size )
        pmd->fp_length = ret_bytes;

    return 0;
}

static void fpRuleGroupPrintRuleCount(RuleGroup* pg, const char* what)
{
    LogMessage("RuleGroup rule summary (%s):\n", what);

    for ( auto& it : pg->pm_list )
    {
        int count = it->group.normal_mpse ?  it->group.normal_mpse->get_pattern_count() : 0;
        int count_ol = it->group.offload_mpse ?  it->group.offload_mpse->get_pattern_count() : 0;

        if ( count )
            LogMessage("\tNormal Pattern Matcher %s: %d\n", it->name, count);

        if ( count_ol )
            LogMessage("\tOffload Pattern Matcher %s: %d\n", it->name, count_ol);
    }

    if ( pg->nfp_rule_count )
        LogMessage("\tNormal Pattern Matcher No content: %u\n", pg->nfp_rule_count);
}

static void fpDeletePMX(void* pv)
{
    if ( pv )
        snort_free(pv);
}

/*
 *  Create the RuleGroup for these PortObject2 entities
 *
 *  This builds the 1st pass multi-pattern state machines for
 *  content and uricontent based on the rules in the PortObjects
 *  hash table.
 */
static void fpCreatePortObject2RuleGroup(SnortConfig* sc, PortObject2* po, PortObject2* poaa)
{
    assert( po );

    po->group = nullptr;
    FastPatternConfig* fp = sc->fast_pattern_config;
    if ( fp->get_debug_print_rule_group_build_details() )
        PortObject2PrintPorts(po);

    /* Check if we have any rules */
    if ( !po->rule_hash )
        return;

    /* create a port_group */
    RuleGroup* pg = new RuleGroup;
    s_group = "port";

    /*
     * Walk the rules in the PortObject and add to
     * the RuleGroup pattern state machine
     *  and to the port group RULE_NODE lists.
     * (The lists are still used in some cases
     *  during detection to walk the rules in a group
     *  so we have to load these as well...fpEvalHeader()... for now.)
     *
     * po   src/dst ports : content/uri and nocontent
     * poaa any-any ports : content/uri and nocontent
     *
     * each PG has src or dst contents, generic-contents, and no-contents
     * (src/dst or any-any ports)
     *
     */
    PortObject2* pox = po;
    while ( pox )
    {
        for (GHashNode* node = pox->rule_hash->find_first();
             node;
             node = pox->rule_hash->find_next())
        {
            unsigned sid, gid;
            int* prindex = (int*)node->data;

            /* be safe - no rule index, ignore it */
            if (prindex == nullptr)
                continue;

            /* look up gid:sid */
            parser_get_rule_ids(*prindex, gid, sid);

            /* look up otn */
            OptTreeNode* otn = OtnLookup(sc->otn_map, gid, sid);
            assert(otn);

            if ( is_network_protocol(otn->snort_protocol_id) )
                fpAddRuleGroupRule(sc, pg, otn, fp, false);
        }

        if (fp->get_debug_print_rule_group_build_details())
            fpRuleGroupPrintRuleCount(pg, pox == po ? "ports" : "any");

        if (pox == poaa)
            break;

        pox = poaa;
    }

    // This might happen if there was ip proto only rules...Don't return failure
    if (fpFinishRuleGroup(sc, pg) != 0)
        return;

    po->group = pg;
    return;
}

/*
 *  Create the port groups for this port table
 */
static void fpCreatePortTableRuleGroups(SnortConfig* sc, PortTable* p, PortObject2* poaa)
{
    int cnt = 1;
    FastPatternConfig* fp = sc->fast_pattern_config;
    if ( fp->get_debug_print_rule_group_build_details() )
        LogMessage("%d Port Groups in Port Table\n",p->pt_mpo_hash->get_count());

    for (GHashNode* node = p->pt_mpo_hash->find_first();
         node;
         node = p->pt_mpo_hash->find_next())
    {
        PortObject2* po = (PortObject2*)node->data;
        if ( !po )
            continue;

        if (fp->get_debug_print_rule_group_build_details())
            LogMessage("Creating Port Group Object %d of %d\n", cnt++, p->pt_mpo_hash->get_count());

        /* if the object is not referenced, don't add it to the RuleGroups
         * as it may overwrite other objects that are more inclusive. */
        if ( !po->port_cnt )
            continue;

        fpCreatePortObject2RuleGroup(sc, po, poaa);
    }
}

/*
 *  Create port group objects for all port tables
 *
 *  note: any ports are standard PortObjects not PortObject2s so we have to
 *  upgrade them for the create port group function
 */
static int fpCreateRuleGroups(SnortConfig* sc, RulePortTables* p)
{
    if (!get_rule_count())
        return 0;

    FastPatternConfig* fp = sc->fast_pattern_config;
    bool log_rule_group_details = fp->get_debug_print_rule_group_build_details();

    /* IP */
    PortObject2* po2 = PortObject2Dup(*p->ip.any);
    PortObject2* add_any_any = fp->get_split_any_any() ? nullptr : po2;

    if ( log_rule_group_details )
        LogMessage("\nIP-SRC ");

    fpCreatePortTableRuleGroups(sc, p->ip.src, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nIP-DST ");

    fpCreatePortTableRuleGroups(sc, p->ip.dst, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nIP-ANY ");

    fpCreatePortObject2RuleGroup(sc, po2, nullptr);
    p->ip.any->group = po2->group;
    po2->group = nullptr;
    PortObject2Free(po2);

    /* ICMP */
    po2 = PortObject2Dup(*p->icmp.any);
    add_any_any = fp->get_split_any_any() ? nullptr : po2;

    if ( log_rule_group_details )
        LogMessage("\nICMP-SRC ");

    fpCreatePortTableRuleGroups(sc, p->icmp.src, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nICMP-DST ");

    fpCreatePortTableRuleGroups(sc, p->icmp.dst, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nICMP-ANY ");

    fpCreatePortObject2RuleGroup(sc, po2, nullptr);
    p->icmp.any->group = po2->group;
    po2->group = nullptr;
    PortObject2Free(po2);

    po2 = PortObject2Dup(*p->tcp.any);
    add_any_any = fp->get_split_any_any() ? nullptr : po2;

    if ( log_rule_group_details )
        LogMessage("\nTCP-SRC ");

    fpCreatePortTableRuleGroups(sc, p->tcp.src, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nTCP-DST ");

    fpCreatePortTableRuleGroups(sc, p->tcp.dst, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nTCP-ANY ");

    fpCreatePortObject2RuleGroup(sc, po2, nullptr);
    p->tcp.any->group = po2->group;
    po2->group = nullptr;
    PortObject2Free(po2);

    /* UDP */
    po2 = PortObject2Dup(*p->udp.any);
    add_any_any = fp->get_split_any_any() ? nullptr : po2;

    if ( log_rule_group_details )
        LogMessage("\nUDP-SRC ");

    fpCreatePortTableRuleGroups(sc, p->udp.src, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nUDP-DST ");

    fpCreatePortTableRuleGroups(sc, p->udp.dst, add_any_any);

    if ( log_rule_group_details )
        LogMessage("\nUDP-ANY ");

    fpCreatePortObject2RuleGroup(sc, po2, nullptr);
    p->udp.any->group = po2->group;
    po2->group = nullptr;
    PortObject2Free(po2);

    /* SVC */
    po2 = PortObject2Dup(*p->svc_any);

    if ( log_rule_group_details )
        LogMessage("\nSVC-ANY ");

    fpCreatePortObject2RuleGroup(sc, po2, nullptr);
    p->svc_any->group = po2->group;
    po2->group = nullptr;
    PortObject2Free(po2);

    return 0;
}

/*
* Build a Port Group for this service based on the list of otns. The final
* port_group pointer is stored using the service name as the key.
*
* p   - hash table mapping services to port_groups
* srvc- service name, key used to store the port_group
*       ...could use a service id instead (bytes, fixed length,etc...)
* list- list of otns for this service
*/
static void fpBuildServiceRuleGroupByServiceOtnList(
    SnortConfig* sc, GHash* p, const char* srvc, SF_LIST* list, FastPatternConfig* fp)
{
    RuleGroup* pg = new RuleGroup;
    s_group = srvc;

    /*
     * add each rule to the service group pattern matchers,
     * or to the no-content rule list
     */
    SF_LNODE* cursor;

    for (OptTreeNode* otn = (OptTreeNode*)sflist_first(list, &cursor);
         otn;
         otn = (OptTreeNode*)sflist_next(&cursor) )
    {
        fpAddRuleGroupRule(sc, pg, otn, fp, true);
    }

    if (fpFinishRuleGroup(sc, pg) != 0)
        return;

    /* Add the port_group using it's service name */
    p->insert(srvc, pg);
}

/*
 * For each service we create a RuleGroup based on the otn's defined to
 * be applicable to that service by the metadata option.
 *
 * Then we lookup the protocol/srvc ordinal in the target-based area
 * and assign the RuleGroup for the srvc to it.
 *
 * spg - service port group (lookup should be by service id/tag)
 *     - this table maintains a port_group ptr for each service
 * srm - service rule map table (lookup by ascii service name)
 *     - this table maintains a SF_LIST ptr (list of rule otns) for each service
 *
 */
static void fpBuildServiceRuleGroups(
    SnortConfig* sc, GHash* spg, RuleGroupVector& sopg, GHash* srm, FastPatternConfig* fp)
{
    for (GHashNode* n = srm->find_first(); n; n = srm->find_next())
    {
        SF_LIST* list = (SF_LIST*)n->data;
        const char* srvc = (const char*)n->key;

        assert(list and srvc);

        fpBuildServiceRuleGroupByServiceOtnList(sc, spg, srvc, list, fp);

        /* Add this RuleGroup to the protocol-ordinal -> port_group table */
        RuleGroup* pg = (RuleGroup*)spg->find(srvc);
        if ( !pg )
        {
            ParseError("*** failed to create and find a port group for '%s'",srvc);
            continue;
        }
        SnortProtocolId snort_protocol_id = sc->proto_ref->find(srvc);
        assert(snort_protocol_id != UNKNOWN_PROTOCOL_ID);
        assert((unsigned)snort_protocol_id < sopg.size());

        sopg[snort_protocol_id] = pg;
    }
}

/*
 * For each proto+dir+service build a RuleGroup
 */
static void fpCreateServiceMapRuleGroups(SnortConfig* sc)
{
    FastPatternConfig* fp = sc->fast_pattern_config;

    sc->spgmmTable = ServiceRuleGroupMapNew();
    sc->sopgTable = new sopg_table_t(sc->proto_ref->get_count());

    fpBuildServiceRuleGroups(sc, sc->spgmmTable->to_srv,
        sc->sopgTable->to_srv, sc->srmmTable->to_srv, fp);

    fpBuildServiceRuleGroups(sc, sc->spgmmTable->to_cli,
        sc->sopgTable->to_cli, sc->srmmTable->to_cli, fp);
}

/*
 *  Print the rule gid:sid based on the otn list
 */
static void fpPrintRuleList(SF_LIST* list)
{
    OptTreeNode* otn;
    SF_LNODE* cursor;

    for ( otn=(OptTreeNode*)sflist_first(list, &cursor);
        otn;
        otn=(OptTreeNode*)sflist_next(&cursor) )
    {
        LogMessage("|   %u:%u\n", otn->sigInfo.gid, otn->sigInfo.sid);
    }
}

static void fpPrintServiceRuleMapTable(GHash* p, const char* dir)
{
    GHashNode* n;

    if ( !p || !p->get_count() )
        return;

    std::string label = "service rule counts - ";
    label += dir;
    LogLabel(label.c_str());

    for (n = p->find_first(); n; n = p->find_next())
    {
        SF_LIST* list;

        list = (SF_LIST*)n->data;
        if ( !list )
            continue;

        if ( !n->key )
            continue;

        LogCount((const char*)n->key, list->count);

        fpPrintRuleList(list);
    }
}

static void fpPrintServiceRuleMaps(SnortConfig* sc)
{
    fpPrintServiceRuleMapTable(sc->srmmTable->to_srv, "to server");
    fpPrintServiceRuleMapTable(sc->srmmTable->to_cli, "to client");
}

static void fp_print_service_rules(SnortConfig* sc, GHash* cli, GHash* srv)
{
    if ( !cli->get_count() and !srv->get_count() )
        return;

    LogLabel("service rule counts          to-srv  to-cli");

    uint16_t idx = 0;
    unsigned ctot = 0, stot = 0;

    while ( const char* svc = sc->proto_ref->get_name_sorted(idx++) )
    {
        SF_LIST* clist = (SF_LIST*)cli->find(svc);
        SF_LIST* slist = (SF_LIST*)srv->find(svc);

        if ( !clist and !slist )
            continue;

        unsigned nc = clist ? clist->count : 0;
        unsigned ns = slist ? slist->count : 0;

        LogMessage("%25.25s: %8u%8u\n", svc, nc, ns);

        ctot += nc;
        stot += ns;
    }
    if ( ctot or stot )
        LogMessage("%25.25s: %8u%8u\n", "total", ctot, stot);
}

static void fp_print_service_rules_by_proto(SnortConfig* sc)
{
    fp_print_service_rules(sc, sc->srmmTable->to_srv, sc->srmmTable->to_cli);
}

static void fp_sum_port_groups(RuleGroup* pg, unsigned& c)
{
    if ( !pg )
        return;

    for ( const auto& it : pg->pm_list )
    {
        if ( it->group.normal_mpse and it->group.normal_mpse->get_pattern_count() )
            c++;
    }
}

static void fp_sum_service_groups(GHash* h, unsigned& c)
{
    for (GHashNode* node = h->find_first();
         node;
         node = h->find_next())
    {
        RuleGroup* pg = (RuleGroup*)node->data;
        fp_sum_port_groups(pg, c);
    }
}

static void fp_print_service_groups(srmm_table_t* srmm, bool label)
{
    unsigned to_srv = 0;
    unsigned to_cli = 0;

    fp_sum_service_groups(srmm->to_srv, to_srv);
    fp_sum_service_groups(srmm->to_cli, to_cli);

    if ( label and (to_srv or to_cli) )
        LogLabel("fast pattern groups");

    LogCount("to_server", to_srv);
    LogCount("to_client", to_cli);
}

static void fp_sum_port_groups(PortTable* tab, unsigned& c)
{
    for (GHashNode* node = tab->pt_mpo_hash->find_first();
         node;
         node = tab->pt_mpo_hash->find_next())
    {
        PortObject2* po = (PortObject2*)node->data;
        fp_sum_port_groups(po->group, c);
        PortObject2Finalize(po);
    }
    PortTableFinalize(tab);
}

static bool fp_print_port_groups(RulePortTables* port_tables)
{
    unsigned src = 0;
    unsigned dst = 0;
    unsigned any = 0;

    fp_sum_port_groups(port_tables->ip.src, src);
    fp_sum_port_groups(port_tables->ip.dst, dst);
    fp_sum_port_groups((RuleGroup*)port_tables->ip.any->group, any);

    PortObjectFinalize(port_tables->ip.any);
    PortObjectFinalize(port_tables->ip.nfp);

    fp_sum_port_groups(port_tables->icmp.src, src);
    fp_sum_port_groups(port_tables->icmp.dst, dst);
    fp_sum_port_groups((RuleGroup*)port_tables->icmp.any->group, any);

    PortObjectFinalize(port_tables->icmp.any);
    PortObjectFinalize(port_tables->icmp.nfp);

    fp_sum_port_groups(port_tables->tcp.src, src);
    fp_sum_port_groups(port_tables->tcp.dst, dst);
    fp_sum_port_groups((RuleGroup*)port_tables->tcp.any->group, any);

    PortObjectFinalize(port_tables->tcp.any);
    PortObjectFinalize(port_tables->tcp.nfp);

    fp_sum_port_groups(port_tables->udp.src, src);
    fp_sum_port_groups(port_tables->udp.dst, dst);
    fp_sum_port_groups((RuleGroup*)port_tables->udp.any->group, any);

    PortObjectFinalize(port_tables->udp.any);
    PortObjectFinalize(port_tables->udp.nfp);

    if ( src or dst or any )
    {
        LogLabel("fast pattern groups");
        LogCount("src", src);
        LogCount("dst", dst);
        LogCount("any", any);
        return true;
    }
    return false;
}

/*
 *  Build Service based RuleGroups using the rules
 *  metadata option service parameter.
 */
static void fpCreateServiceRuleGroups(SnortConfig* sc)
{
    FastPatternConfig* fp = sc->fast_pattern_config;

    sc->srmmTable = ServiceMapNew();

    fpCreateServiceMaps(sc);
    fp_print_service_rules_by_proto(sc);

    if ( fp->get_debug_print_rule_group_build_details() )
        fpPrintServiceRuleMaps(sc);

    fpCreateServiceMapRuleGroups(sc);

    if (fp->get_debug_print_rule_group_build_details())
        fpPrintServiceRuleGroupSummary(sc);

    ServiceMapFree(sc->srmmTable);
    sc->srmmTable = nullptr;
}

static unsigned can_build_mt(FastPatternConfig* fp)
{
    if ( Snort::is_reloading() )
        return false;

    const MpseApi* search_api = fp->get_search_api();
    assert(search_api);

    if ( !MpseManager::parallel_compiles(search_api) )
        return false;

    const MpseApi* offload_search_api = fp->get_offload_search_api();

    if ( offload_search_api and !MpseManager::parallel_compiles(offload_search_api) )
        return false;

    return true;
}

/*
*  7/2007 - man
*  Build Pattern Groups for 1st pass of content searching using
*  multi-pattern search method.
*/
int fpCreateFastPacketDetection(SnortConfig* sc)
{
    assert(sc);

    RulePortTables* port_tables = sc->port_tables;
    FastPatternConfig* fp = sc->fast_pattern_config;
    bool log_rule_group_details = fp->get_debug_print_rule_group_build_details();

    assert(port_tables);
    assert(fp);

    if ( !get_rule_count() )
    {
        sc->sopgTable = new sopg_table_t(sc->proto_ref->get_count());
        return 0;
    }

    mpse_count = 0;
    offload_mpse_count = 0;
    fp_only = 0;

    MpseManager::start_search_engine(fp->get_search_api());

    if ( log_rule_group_details )
        LogMessage("Creating Port Groups....\n");

    fpCreateRuleGroups(sc, port_tables);

    if ( log_rule_group_details )
    {
        LogMessage("Port Groups Done....\n");
        LogMessage("Creating Rule Maps....\n");
    }

    fpCreateRuleMaps(sc, port_tables);

    if ( log_rule_group_details )
    {
        LogMessage("Rule Maps Done....\n");
        LogMessage("Creating Service Based Rule Maps....\n");
    }

    fpCreateServiceRuleGroups(sc);

    if ( log_rule_group_details )
        LogMessage("Service Based Rule Maps Done....\n");

    unsigned mpse_loaded = 0;
    unsigned mpse_dumped = 0;

    if ( !sc->test_mode() or sc->mem_check() )
    {
        if ( !fp->get_rule_db_dir().empty() )
            mpse_loaded = fp_deserialize(sc, fp->get_rule_db_dir());

        unsigned c = compile_mpses(sc, can_build_mt(fp));
        unsigned expected = mpse_count + offload_mpse_count;

        if ( c != expected )
            ParseError("Failed to compile %u search engines", expected - c);
    }

    bool label = fp_print_port_groups(port_tables);
    fp_print_service_groups(sc->spgmmTable, !label);

    if ( !sc->rule_db_dir.empty() )
        mpse_dumped = fp_serialize(sc, sc->rule_db_dir);

    if ( mpse_count )
    {
        LogLabel("search engine");
        MpseManager::print_mpse_summary(fp->get_search_api());
    }

    if ( offload_mpse_count and (fp->get_offload_search_api()))
    {
        LogLabel("offload search engine");
        MpseManager::print_mpse_summary(fp->get_offload_search_api());
    }

    LogCount("truncated patterns", fp->get_num_patterns_truncated());
    LogCount("fast pattern only", fp_only);
    LogCount("mpse_loaded", mpse_loaded);
    LogCount("mpse_dumped", mpse_dumped);

    MpseManager::setup_search_engine(fp->get_search_api(), sc);

    return 0;
}

void fpDeleteFastPacketDetection(SnortConfig* sc)
{
    if (sc == nullptr)
        return;

    /* Cleanup the detection option tree */
    delete sc->detection_option_hash_table;
    delete sc->detection_option_tree_hash_table;

    fpFreeRuleMaps(sc);
    ServiceRuleGroupMapFree(sc->spgmmTable);

    if ( sc->sopgTable )
        delete sc->sopgTable;
}

static void print_nfp_info(const char* group, OptTreeNode* otn)
{
    if ( otn->warned_fp() )
        return;

    const char* type = otn->longestPatternLen ? "negated" : "no";

    ParseWarning(WARN_RULES, "%s rule %u:%u:%u has %s fast pattern",
        group, otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev, type);

    otn->set_warned_fp();
}

void get_pattern_info(const PatternMatchData* pmd, string& hex, string& txt, string& opts)
{
    char buf[8];

    for ( unsigned i = 0; i < pmd->pattern_size; ++i )
    {
        snprintf(buf, sizeof(buf), "%2.02X ", (uint8_t)pmd->pattern_buf[i]);
        hex += buf;
        txt += isprint(pmd->pattern_buf[i]) ? pmd->pattern_buf[i] : '.';
    }
    opts = "(";
    if ( pmd->is_fast_pattern() )
        opts += " user";
    if ( pmd->is_negated() )
        opts += " negated";
    opts += " )";
}

static void print_fp_info(const char* group, const OptTreeNode* otn, const PatternMatchData* pmd)
{
    std::string hex, txt, opts;

    get_pattern_info(pmd, hex, txt, opts);
    LogMessage("FP %s %u:%u:%u %s[%d] = '%s' |%s| %s\n",
        group, otn->sigInfo.gid, otn->sigInfo.sid, otn->sigInfo.rev,
        pmd->sticky_buf, pmd->pattern_size, txt.c_str(), hex.c_str(), opts.c_str());
}

