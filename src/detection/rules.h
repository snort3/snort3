//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "actions/actions.h"
#include "main/policy.h"

#define GID_DEFAULT          1
#define GID_SESSION        135

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
    snort::IpsAction* action;
    struct RuleListNode* ruleListNode;
};

// for top-level rule lists by type (alert, drop, etc.)
struct RuleListNode
{
    ListHead* RuleList;   /* The rule list associated with this node */
    snort::Actions::Type mode;        /* the rule mode */
    int evalIndex;        /* eval index for this rule set */
    char* name;           /* name of this rule list */
    RuleListNode* next;   /* the next RuleListNode */
};

class RuleState
{
public:
    RuleState(unsigned g, unsigned s, IpsPolicy::Action a, IpsPolicy::Enable e) :
        gid(g), sid(s), action(a), enable(e)
    { policy = snort::get_ips_policy()->policy_id; }

    virtual ~RuleState() = default;

    void apply(snort::SnortConfig*);
    void update_rtn(RuleTreeNode*);

private:
    unsigned gid;
    unsigned sid;
    unsigned policy;

    IpsPolicy::Action action;
    IpsPolicy::Enable enable;

    void apply(snort::SnortConfig*, OptTreeNode* otn, unsigned ips_num);
    RuleTreeNode* dup_rtn(RuleTreeNode*);
};

#endif

