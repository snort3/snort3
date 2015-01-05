/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef PARSER_H
#define PARSER_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include "snort.h"
#include "rules.h"
#include "treenodes.h"
#include "protocols/packet.h"
#include "main/policy.h"
#include "sflsq.h"
#include "util.h"
#include "parser/cmd_line.h"
#include "detection/sfrim.h"

unsigned get_parse_errors();
unsigned get_parse_warnings();

const char* get_parse_file();
void get_parse_location(const char*& name, unsigned& line);
void push_parse_location(const char* name, unsigned line = 0);

void pop_parse_location();
void inc_parse_position();

/* rule setup funcs */
SnortConfig * ParseSnortConf(const SnortConfig*);
void ParseRules(SnortConfig *);

void OrderRuleLists(SnortConfig *, const char *);
void PrintRuleOrder(RuleListNode *);

const char * VarGet(SnortConfig *, const char *);
char * ProcessFileOption(SnortConfig *, const char *);
void SetRuleStates(SnortConfig *);

void ParserCleanup(void);
void FreeRuleLists(SnortConfig *);
void VarTablesFree(SnortConfig *);
void PortTablesFree(rule_port_tables_t *);

void parser_append_rules(const char*);

void ConfigureSideChannelModules(SnortConfig *);

SO_PUBLIC NORETURN void ParseAbort(const char *, ...);
SO_PUBLIC void ParseError(const char *, ...);
SO_PUBLIC void ParseWarning(const char *, ...);
SO_PUBLIC void ParseMessage(const char *, ...);

int ParseBool(const char *arg);

int addRtnToOtn(struct OptTreeNode*, RuleTreeNode*);
int addRtnToOtn(struct OptTreeNode*, RuleTreeNode*, PolicyId);

RuleTreeNode* deleteRtnFromOtn(struct OptTreeNode*);
RuleTreeNode* deleteRtnFromOtn(struct OptTreeNode*, PolicyId);

/*Get RTN for a given OTN and policyId.
 *
 * @param otn pointer to structure OptTreeNode.
 * @param policyId policy id
 *
 * @return pointer to deleted RTN, NULL otherwise.
 */
static inline RuleTreeNode *getRtnFromOtn(
    const struct OptTreeNode* otn, PolicyId policyId)
{
    if (otn && otn->proto_nodes && (otn->proto_node_num > (unsigned)policyId))
    {
        return otn->proto_nodes[policyId];
    }

    return NULL;
}

static inline RuleTreeNode *getRtnFromOtn(
    const struct OptTreeNode* otn)
{
    return getRtnFromOtn(otn, get_ips_policy()->policy_id);
}

static inline RuleTreeNode *getRuntimeRtnFromOtn(
    const struct OptTreeNode *otn)
{
    return getRtnFromOtn(otn);
}

extern rule_index_map_t * ruleIndexMap;

ListHead* CreateRuleType(SnortConfig*, const char*, RuleType, int, ListHead*);

void FreeRuleTreeNode(RuleTreeNode*);
void DestroyRuleTreeNode(RuleTreeNode*);

void rule_index_map_print_index(int index, char* buf, int);

#endif

