//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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

// rules.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"

#include <cassert>

#include "log/messages.h"
#include "hash/xhash.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"

#include "treenodes.h"

using namespace snort;

bool operator< (const RuleKey& lhs, const RuleKey& rhs)
{
    if ( lhs.policy_id < rhs.policy_id )
        return true;

    if ( lhs.policy_id == rhs.policy_id )
    {
        if ( lhs.gid < rhs.gid )
            return true;

        if ( lhs.gid == rhs.gid and lhs.sid < rhs.sid )
            return true;
    }
    return false;
}

void RuleStateMap::apply(SnortConfig* sc)
{
    for ( auto it : map )
    {
        const RuleKey& k = it.first;
        OptTreeNode* otn = OtnLookup(sc->otn_map, k.gid, k.sid);
        auto empty_ips_id = get_empty_ips_policy(sc)->policy_id;

        if ( !otn )
            ParseWarning(WARN_RULES, "Rule state specified for unknown rule %u:%u", k.gid, k.sid);
        else
        {
            if ( sc->global_rule_state )
            {
                for ( unsigned i = 0; i < sc->policy_map->ips_policy_count(); i++ )
                {
                    auto policy = sc->policy_map->get_ips_policy(i);
                    if ( policy and (policy->policy_id != empty_ips_id) )
                        apply(sc, otn, i, it.second);
                }
            }
            else
                apply(sc, otn, it.first.policy_id, it.second);
        }
    }
}

void RuleStateMap::apply(
    SnortConfig* sc, OptTreeNode* otn, unsigned ips_num, RuleState& s)
{
    IpsPolicy* policy = nullptr;
    RuleTreeNode* rtn = getRtnFromOtn(otn, ips_num);

    if ( !rtn )
        if ( ips_num and (rtn = getRtnFromOtn(otn, 0)) )
            policy = sc->policy_map->get_ips_policy(ips_num);

    if ( !rtn )
        return;

    if ( policy )
        policy->rules_shared++;

    rtn = dup_rtn(rtn);
    update_rtn(rtn, s);
    addRtnToOtn(sc, otn, rtn, ips_num);
}

RuleTreeNode* RuleStateMap::dup_rtn(RuleTreeNode* rtn)
{
    RuleTreeNode* ret = new RuleTreeNode(*rtn);

    ret->otnRefCount = 0;
    ret->sip = sfvar_deep_copy(rtn->sip);
    ret->dip = sfvar_deep_copy(rtn->dip);

    RuleFpList* from = rtn->rule_func;

    if ( from )
    {
        RuleFpList* to = new RuleFpList(*from);
        to->next = nullptr;
        ret->rule_func = to;

        for ( from = from->next; from; from = from->next )
        {
            to->next = new RuleFpList(*from);
            to = to->next;
            to->next = nullptr;
        }
    }

    return ret;
}

void RuleStateMap::update_rtn(RuleTreeNode* rtn, const RuleState& s)
{
    switch ( s.enable )
    {
    case IpsPolicy::DISABLED: rtn->clear_enabled(); break;
    case IpsPolicy::ENABLED: rtn->set_enabled(); break;
    case IpsPolicy::INHERIT_ENABLE: break;
    }
    rtn->action = s.action;
}

