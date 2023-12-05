//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef RULES_H
#define RULES_H

// misc rule and rule list support
// FIXIT-L refactor this header

#include <map>
#include <string>

#include "actions/actions.h"
#include "main/policy.h"

#define GID_DEFAULT          1
#define GID_SESSION        135

#define GID_BUILTIN_MIN     40
#define GID_BUILTIN_MAX    999

#define SESSION_EVENT_SYN_RX 1
#define SESSION_EVENT_SETUP  2
#define SESSION_EVENT_CLEAR  3

#define EventIsInternal(gid) ((gid) == GID_SESSION)

namespace snort
{
    class IpsAction;
    struct SnortConfig;
}
struct OutputSet;
struct RuleTreeNode;

struct ListHead
{
    OutputSet* LogList;
    OutputSet* AlertList;
    struct RuleListNode* ruleListNode;
};

// for top-level rule lists by type (alert, drop, etc.)
struct RuleListNode
{
    ListHead* RuleList;   /* The rule list associated with this node */
    Actions::Type mode;        /* the rule mode */
    unsigned evalIndex;        /* eval index for this rule set */
    char* name;           /* name of this rule list */
    RuleListNode* next;   /* the next RuleListNode */
};

struct RuleKey
{
    unsigned policy_id;
    unsigned gid;
    unsigned sid;

    friend bool operator< (const RuleKey&, const RuleKey&);
};

struct RuleState
{
    std::string rule_action;
    uint8_t action;
    IpsPolicy::Enable enable;
};

class RuleStateMap
{
public:
    void add(const RuleKey& key, const RuleState& state)
    { map[key] = state; }

    void apply(snort::SnortConfig*);

private:
    RuleTreeNode* dup_rtn(RuleTreeNode*, IpsPolicy*);
    void update_rtn(snort::SnortConfig*, RuleTreeNode*, const RuleState&);
    void apply(snort::SnortConfig*, OptTreeNode*, unsigned ips_num, const RuleState&);

private:
    std::map<RuleKey, RuleState> map;
};

#endif

