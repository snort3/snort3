//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parser.h"

#include <pcap.h>

#include <cassert>
#include <iostream>

#include "detection/fp_config.h"
#include "detection/rules.h"
#include "detection/sfrim.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfthreshold.h"
#include "hash/hashfcn.h"
#include "hash/xhash.h"
#include "helpers/directory.h"
#include "log/messages.h"
#include "main/modules.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "ports/port_object.h"
#include "ports/port_table.h"
#include "ports/rule_port_tables.h"
#include "sfip/sf_ipvar.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "config_file.h"
#include "mstring.h"
#include "parse_conf.h"
#include "parse_rule.h"
#include "parse_stream.h"
#include "vars.h"

using namespace snort;

static struct rule_index_map_t* ruleIndexMap = nullptr;

static std::string s_aux_rules;

//-------------------------------------------------------------------------
// private / implementation methods
//-------------------------------------------------------------------------

static void FreeRuleTreeNodes(SnortConfig* sc)
{
    if ( !sc->otn_map )
        return;

    for ( GHashNode* hashNode = ghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = ghash_findnext(sc->otn_map) )
    {
        OptTreeNode* otn = (OptTreeNode*)hashNode->data;

        for ( PolicyId policyId = 0; policyId < otn->proto_node_num; policyId++ )
        {
            RuleTreeNode* rtn = getRtnFromOtn(otn, policyId);
            if ( !rtn )
                continue;
            rtn->otnRefCount--;
            DestroyRuleTreeNode(rtn);
            otn->proto_nodes[policyId] = nullptr;
        }
    }
}

static void FreeOutputLists(ListHead* list)
{
    if ( list->AlertList )
        EventManager::release_outputs(list->AlertList);

    if ( list->LogList )
        EventManager::release_outputs(list->LogList);
}

/* Finish processing/setup Port Tables */
static void finish_portlist_table(FastPatternConfig* fp, const char* s, PortTable* pt)
{
    PortTableSortUniqRules(pt);

    if (  fp->get_debug_print_rule_groups_uncompiled() )
    {
        LogMessage("***\n***Port-Table : %s Ports/Rules-UnCompiled\n",s);
        PortTablePrintInputEx(pt, rule_index_map_print_index);
    }

    PortTableCompile(pt);

    if (  fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("***\n***Port-Table : %s Ports/Rules-Compiled\n",s);
        PortTablePrintCompiledEx(pt, rule_index_map_print_index);
        LogMessage("*** End of Compiled Group\n");
    }
}

static void PortTablesFinish(RulePortTables* port_tables, FastPatternConfig* fp)
{
    if ( fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("IP-Any-Any Port List\n");
        PortObjectPrintEx(port_tables->ip.any, rule_index_map_print_index);
    }

    finish_portlist_table(fp, "ip src", port_tables->ip.src);
    finish_portlist_table(fp, "ip dst", port_tables->ip.dst);

    if ( fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("*** ICMP-Any-Any Port List\n");
        PortObjectPrintEx(port_tables->icmp.any, rule_index_map_print_index);
    }

    finish_portlist_table(fp, "icmp src", port_tables->icmp.src);
    finish_portlist_table(fp, "icmp dst", port_tables->icmp.dst);

    if ( fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("*** TCP-Any-Any Port List\n");
        PortObjectPrintEx(port_tables->tcp.any, rule_index_map_print_index);
    }

    finish_portlist_table(fp, "tcp src", port_tables->tcp.src);
    finish_portlist_table(fp, "tcp dst", port_tables->tcp.dst);

    if ( fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("*** UDP-Any-Any Port List\n");
        PortObjectPrintEx(port_tables->udp.any, rule_index_map_print_index);
    }

    finish_portlist_table(fp, "udp src", port_tables->udp.src);
    finish_portlist_table(fp, "udp dst", port_tables->udp.dst);

    if ( fp->get_debug_print_rule_groups_compiled() )
    {
        LogMessage("*** SVC-Any-Any Port List\n");
        PortObjectPrintEx(port_tables->svc_any, rule_index_map_print_index);
    }

    RuleListSortUniq(port_tables->ip.any->rule_list);
    RuleListSortUniq(port_tables->icmp.any->rule_list);
    RuleListSortUniq(port_tables->tcp.any->rule_list);
    RuleListSortUniq(port_tables->udp.any->rule_list);
    RuleListSortUniq(port_tables->svc_any->rule_list);

    RuleListSortUniq(port_tables->ip.nfp->rule_list);
    RuleListSortUniq(port_tables->icmp.nfp->rule_list);
    RuleListSortUniq(port_tables->tcp.nfp->rule_list);
    RuleListSortUniq(port_tables->udp.nfp->rule_list);
}

static void OtnInit(SnortConfig* sc)
{
    if (sc == nullptr)
        return;

    /* Don't initialize this more than once */
    if ( sc->otn_map != nullptr )
        return;

    /* Init sid-gid -> otn map */
    sc->otn_map = OtnLookupNew();
    if (sc->otn_map == nullptr)
        ParseAbort("otn_map ghash_new failed.");
}

static RuleListNode* addNodeToOrderedList(RuleListNode* ordered_list,
    RuleListNode* node, int evalIndex)
{
    RuleListNode* prev;

    prev = ordered_list;

    /* set the eval order for this rule set */
    node->evalIndex = evalIndex;

    if (!prev)
    {
        ordered_list = node;
    }
    else
    {
        while (prev->next)
            prev = prev->next;
        prev->next = node;
    }

    node->next = nullptr;

    return ordered_list;
}

static bool parse_file(SnortConfig* sc, Shell* sh, bool is_fatal, bool is_root)
{
    const char* fname = sh->get_file();

    if ( !fname || !*fname )
        return false;

    bool success = sh->configure(sc, is_fatal, is_root);
    return success;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void parser_init()
{
    parse_rule_init();

    ruleIndexMap = RuleIndexMapCreate();

    if ( !ruleIndexMap )
        ParseAbort("failed to create rule index map.");
}

void parser_term(SnortConfig*)
{
    parse_rule_term();
    RuleIndexMapFree(ruleIndexMap);
    ruleIndexMap = nullptr;
}

SnortConfig* ParseSnortConf(const SnortConfig* boot_conf, const char* fname, bool is_fatal)
{
    SnortConfig* sc = new SnortConfig(SnortConfig::get_conf()->proto_ref);
    SnortConfig::set_parser_conf(sc);

    sc->logging_flags = boot_conf->logging_flags;
    sc->tweaks = boot_conf->tweaks;

    VarNode* tmp = boot_conf->var_list;

    if ( !fname )
        fname = get_snort_conf();

    if ( !fname )
        fname = "";

    sc->port_tables = PortTablesNew();

    OtnInit(sc);

    sc->fast_pattern_config = new FastPatternConfig();
    sc->event_queue_config = EventQueueConfigNew();
    sc->threshold_config = ThresholdConfigNew();
    sc->rate_filter_config = RateFilter_ConfigNew();
    sc->detection_filter_config = DetectionFilterConfigNew();

    /* Add command line defined variables - duplicates will already
     * have been resolved */
    while (tmp != nullptr)
    {
        AddVarToTable(sc, tmp->name, tmp->value);
        tmp = tmp->next;
    }

    // get overrides from cmd line
    Shell* sh = boot_conf->policy_map->get_shell();
    sc->policy_map->get_shell()->set_overrides(sh);

    if ( *fname )
    {
        sh = sc->policy_map->get_shell();
        sh->set_file(fname);
    }

    for ( unsigned i = 0; true; i++ )
    {
        sh = sc->policy_map->get_shell(i);

        if ( !sh )
            break;

        set_policies(sc, sh);

        if (!parse_file(sc, sh, is_fatal, (i == 0)))
            return sc;
    }

    set_default_policy(sc);
    return sc;
}

void FreeRuleTreeNode(RuleTreeNode* rtn)
{
    assert(rtn and rtn->otnRefCount == 0);

    if (rtn->sip)
        sfvar_free(rtn->sip);

    if (rtn->dip)
        sfvar_free(rtn->dip);

    RuleFpList* idx = rtn->rule_func;

    while (idx)
    {
        RuleFpList* tmp = idx;
        idx = idx->next;
        delete tmp;
    }
}

void DestroyRuleTreeNode(RuleTreeNode* rtn)
{
    assert(rtn);

    if (rtn->otnRefCount != 0)
        return;

    FreeRuleTreeNode(rtn);
    delete rtn;
}

void ParseRules(SnortConfig* sc)
{
    for ( unsigned idx = 0; idx < sc->policy_map->ips_policy_count(); ++idx )
    {
        set_ips_policy(sc, idx);
        IpsPolicy* p = sc->policy_map->get_ips_policy(idx);

        if ( p->enable_builtin_rules )
            ModuleManager::load_rules(sc);

        if ( !p->include.empty() )
        {
            std::string path = p->includer;
            const char* file = p->include.c_str();
            const char* code = get_config_file(file, path);
            push_parse_location(code, path.c_str(), file);
            parse_rules_file(sc, path.c_str());
            pop_parse_location();
        }

        if ( !p->rules.empty() )
        {
            push_parse_location("C", p->includer.c_str(), "ips.rules");
            parse_rules_string(sc, p->rules.c_str());
            pop_parse_location();
        }

        if ( !p->states.empty() )
        {
            push_parse_location("C", p->includer.c_str(), "ips.states");
            parse_rules_string(sc, p->states.c_str());
            pop_parse_location();
        }

        if ( !idx and !s_aux_rules.empty() )
        {
            p->includer.clear();
            push_parse_location("W", "./", "rule args");
            parse_rules_string(sc, s_aux_rules.c_str());
            pop_parse_location();
        }

        if ( !idx and sc->stdin_rules )
        {
            LogMessage("Reading rules until EOF or a line starting with END\n");
            push_parse_location("W", "./", "stdin");
            parse_stream(std::cin, sc);
            pop_parse_location();
        }
    }

    set_ips_policy(sc, 0);

    /* Compile/Finish and Print the PortList Tables */
    PortTablesFinish(sc->port_tables, sc->fast_pattern_config);

    parse_rule_print();
}

/****************************************************************************
 *
 * Function: CreateRuleType
 *
 * Purpose: Creates a new type of rule and adds it to the end of the rule list
 *
 * Arguments: name = name of this rule type
 *            mode = the mode for this rule type
 *            rval = return value for this rule type (for detect events)
 *
 * Returns: the ListHead for the rule type
 *
 ***************************************************************************/
ListHead* CreateRuleType(SnortConfig* sc, const char* name, Actions::Type mode)
{
    RuleListNode* node;
    int evalIndex = 0;

    if (sc == nullptr)
        return nullptr;

    node = (RuleListNode*)snort_calloc(sizeof(RuleListNode));

    /* If this is the first rule list node, then we need to
     * create a new list. */
    if (sc->rule_lists == nullptr)
    {
        sc->rule_lists = node;
    }
    else
    {
        RuleListNode* tmp = sc->rule_lists;
        RuleListNode* last;

        do
        {
            /* We do not allow multiple rules types with the same name. */
            if (strcasecmp(tmp->name, name) == 0)
            {
                snort_free(node);
                return nullptr;
            }

            evalIndex++;
            last = tmp;
            tmp = tmp->next;
        }
        while (tmp != nullptr);

        last->next = node;
    }

    node->RuleList = (ListHead*)snort_calloc(sizeof(ListHead));
    node->RuleList->ruleListNode = node;
    node->mode = mode;
    node->name = snort_strdup(name);
    node->evalIndex = evalIndex;

    sc->evalOrder[node->mode] =  evalIndex;
    sc->num_rule_types++;

    return node->RuleList;
}

void FreeRuleLists(SnortConfig* sc)
{
    FreeRuleTreeNodes(sc);

    RuleListNode* node = sc->rule_lists;

    while (node != nullptr)
    {
        RuleListNode* tmp = node;
        node = node->next;

        FreeOutputLists(tmp->RuleList);
        snort_free(tmp->RuleList);

        if (tmp->name)
            snort_free(tmp->name);

        snort_free(tmp);
    }

    sc->rule_lists = nullptr;
}

void OrderRuleLists(SnortConfig* sc)
{
    int evalIndex = 0;
    RuleListNode* ordered_list = nullptr;

    const char* order = sc->rule_order.c_str();
    if ( !*order )
        order = "pass drop alert log";  // FIXIT-H apply builtin module defaults

    int num_toks;
    char** toks = mSplit(order, " \t", 0, &num_toks, 0);

    for ( int i = 0; i < num_toks; i++ )
    {
        RuleListNode* prev = nullptr;
        RuleListNode* node = sc->rule_lists;

        while (node != nullptr)
        {
            if (strcmp(toks[i], node->name) == 0)
            {
                if (prev == nullptr)
                    sc->rule_lists = node->next;
                else
                    prev->next = node->next;

                ordered_list = addNodeToOrderedList(ordered_list, node, evalIndex++);
                sc->evalOrder[node->mode] = evalIndex;
                break;
            }
            else
            {
                prev = node;
                node = node->next;
            }
        }
        // ignore rule types that aren't in use
    }

    mSplitFree(&toks, num_toks);

    /* anything left in the rule lists needs to be moved to the ordered lists */
    while (sc->rule_lists != nullptr)
    {
        RuleListNode* node = sc->rule_lists;
        sc->rule_lists = node->next;
        ordered_list = addNodeToOrderedList(ordered_list, node, evalIndex++);
        sc->evalOrder[node->mode] =  evalIndex;
    }

    sc->rule_lists = ordered_list;
}

RuleTreeNode* deleteRtnFromOtn(OptTreeNode* otn, PolicyId policyId, SnortConfig* sc, bool remove)
{
    if (otn->proto_nodes and (otn->proto_node_num >= (policyId+1)))
    {
        RuleTreeNode* rtn = getRtnFromOtn(otn, policyId);
        otn->proto_nodes[policyId] = nullptr;

        if ( rtn )
        {
            rtn->otnRefCount--;

            if ( remove )
            {
                assert(sc and sc->rtn_hash_table);
                RuleTreeNodeKey key { rtn, policyId };
                xhash_remove(sc->rtn_hash_table, &key);
            }
        }
        return rtn;
    }
    return nullptr;
}

RuleTreeNode* deleteRtnFromOtn(OptTreeNode* otn, SnortConfig* sc)
{
    return deleteRtnFromOtn(otn, get_ips_policy()->policy_id, sc);
}

static uint32_t rtn_hash_func(HashFnc*, const unsigned char* k, int)
{
    uint32_t a,b,c;
    const RuleTreeNodeKey* rtnk = (const RuleTreeNodeKey*)k;
    RuleTreeNode* rtn = rtnk->rtn;

    a = rtn->action;
    b = rtn->flags;
    c = (uint32_t)(uintptr_t)rtn->listhead;

    mix(a,b,c);

    a += (uint32_t)(uintptr_t)rtn->src_portobject;
    b += (uint32_t)(uintptr_t)rtn->dst_portobject;
    c += (uint32_t)(uintptr_t)rtnk->policyId;

    finalize(a,b,c);

    return c;
}

static int rtn_compare_func(const void* k1, const void* k2, size_t)
{
    const RuleTreeNodeKey* rtnk1 = (const RuleTreeNodeKey*)k1;
    const RuleTreeNodeKey* rtnk2 = (const RuleTreeNodeKey*)k2;

    if (!rtnk1 || !rtnk2)
        return 1;

    if (rtnk1->policyId != rtnk2->policyId)
        return 1;

    if (same_headers(rtnk1->rtn, rtnk2->rtn))
        return 0;

    return 1;
}

int addRtnToOtn(SnortConfig* sc, OptTreeNode* otn, RuleTreeNode* rtn, PolicyId policyId)
{
    if (otn->proto_node_num <= policyId)
    {
        /* realloc the list, initialize missing elements to 0 and add
         * policyId */
        unsigned int numNodes = (policyId + 1);
        RuleTreeNode** tmpNodeArray =
            (RuleTreeNode**)snort_calloc(numNodes, sizeof(RuleTreeNode*));

        /* copy original contents, the remaining elements are already
         * zeroed out by snort_calloc */
        if (otn->proto_nodes)
        {
            memcpy(tmpNodeArray, otn->proto_nodes,
                sizeof(RuleTreeNode*) * otn->proto_node_num);
            snort_free(otn->proto_nodes);
        }

        otn->proto_node_num = numNodes;
        otn->proto_nodes = tmpNodeArray;
    }

    RuleTreeNode* curr = otn->proto_nodes[policyId];

    if ( curr )
    {
        deleteRtnFromOtn(otn, policyId, sc, (curr->otnRefCount == 1));
        DestroyRuleTreeNode(curr);
    }
    otn->proto_nodes[policyId] = rtn;
    rtn->otnRefCount++;

    if (!sc->rtn_hash_table)
    {
        sc->rtn_hash_table = xhash_new(
            10000, sizeof(RuleTreeNodeKey), 0, 0, 0, nullptr, nullptr, 1);

        if (sc->rtn_hash_table == nullptr)
            FatalError("Failed to create rule tree node hash table\n");

        xhash_set_keyops(sc->rtn_hash_table, rtn_hash_func, rtn_compare_func);
    }

    RuleTreeNodeKey key;
    memset(&key, 0, sizeof(key));
    key.rtn = rtn;
    key.policyId = policyId;
    xhash_add(sc->rtn_hash_table, &key, rtn);

    return 0;
}

int addRtnToOtn(SnortConfig* sc, OptTreeNode* otn, RuleTreeNode* rtn)
{
    return addRtnToOtn(sc, otn, rtn, get_ips_policy()->policy_id);
}

void rule_index_map_print_index(int index, char* buf, int bufsize)
{
    unsigned gid, sid;
    parser_get_rule_ids(index, gid, sid);
    SnortSnprintfAppend(buf, bufsize, "%u:%u ", gid, sid);
}

void parser_get_rule_ids(int idx, unsigned& gid, unsigned& sid)
{
    assert(ruleIndexMap);
    RuleIndexMapGet(ruleIndexMap, idx, gid, sid);
}

int parser_get_rule_index(unsigned gid, unsigned sid)
{
    assert(ruleIndexMap);
    return RuleIndexMapAdd(ruleIndexMap, gid, sid);
}

void parser_append_rules(const char* s)
{
    s_aux_rules += s;
    s_aux_rules += "\n";
}

void parser_append_includes(const char* d)
{
    Directory dir(d);
    const char* f;

    while ( (f = dir.next()) )
    {
        std::string s = "include ";
        s += f;
        parser_append_rules(s.c_str());
    }
}

