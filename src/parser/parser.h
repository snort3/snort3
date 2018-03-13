//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef PARSER_H
#define PARSER_H

#include "detection/rules.h"
#include "detection/treenodes.h"
#include "main/policy.h"

namespace snort
{
struct SnortConfig;
}

void parser_init();
void parser_term(snort::SnortConfig*);

// line > 0 implies name is non-null
void get_parse_location(const char*& name, unsigned& line);

// use line = 0 for lua to suppress line numbers for errors or warnings
void push_parse_location(const char* name, unsigned line = 1);

void pop_parse_location();
void inc_parse_position();

snort::SnortConfig* ParseSnortConf(const snort::SnortConfig*, const char* fname = nullptr);
void ParseRules(snort::SnortConfig*);

void OrderRuleLists(snort::SnortConfig*, const char*);
void PrintRuleOrder(RuleListNode*);

char* ProcessFileOption(snort::SnortConfig*, const char*);
void SetRuleStates(snort::SnortConfig*);

void FreeRuleLists(snort::SnortConfig*);
void VarTablesFree(snort::SnortConfig*);

void parser_append_rules(const char*);

int ParseBool(const char* arg);

int addRtnToOtn(snort::SnortConfig*, struct OptTreeNode*, RuleTreeNode*);
int addRtnToOtn(snort::SnortConfig*, struct OptTreeNode*, RuleTreeNode*, PolicyId);

bool same_headers(RuleTreeNode*, RuleTreeNode*);
RuleTreeNode* deleteRtnFromOtn(OptTreeNode*, snort::SnortConfig* sc = nullptr);
RuleTreeNode* deleteRtnFromOtn(struct OptTreeNode*, PolicyId, snort::SnortConfig* sc = nullptr, bool remove = true);

inline RuleTreeNode* getRtnFromOtn(const struct OptTreeNode* otn, PolicyId policyId)
{
    if (otn && otn->proto_nodes && (otn->proto_node_num > (unsigned)policyId))
    {
        return otn->proto_nodes[policyId];
    }
    return nullptr;
}

inline RuleTreeNode* getRtnFromOtn(const struct OptTreeNode* otn)
{
    return getRtnFromOtn(otn, snort::get_ips_policy()->policy_id);
}

inline RuleTreeNode* getRuntimeRtnFromOtn(const struct OptTreeNode* otn)
{
    return getRtnFromOtn(otn);
}

ListHead* CreateRuleType(snort::SnortConfig* sc, const char* name, snort::Actions::Type);

void FreeRuleTreeNode(RuleTreeNode*);
void DestroyRuleTreeNode(RuleTreeNode*);

int parser_get_rule_index(unsigned gid, unsigned sid);
void parser_get_rule_ids(int index, unsigned& gid, unsigned& sid);
void rule_index_map_print_index(int index, char* buf, int);

struct RuleTreeNodeKey
{
    RuleTreeNode* rtn;
    PolicyId policyId;
};

extern bool parsing_follows_files;
#endif

