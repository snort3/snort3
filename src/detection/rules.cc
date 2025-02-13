//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "parser/parse_rule.h"
#include "ports/port_object.h"
#include "ports/port_var_table.h"
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
    for ( const auto & it : map )
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
    SnortConfig* sc, OptTreeNode* otn, unsigned ips_num, const RuleState& s)
{
    IpsPolicy* policy = nullptr;
    RuleTreeNode* b_rtn = getRtnFromOtn(otn, ips_num);

    if ( !b_rtn and ips_num and (b_rtn = getRtnFromOtn(otn, 0)) )
        policy = sc->policy_map->get_ips_policy(ips_num);

    if ( !b_rtn )
        return;

    if ( policy )
        policy->rules_shared++;

    RuleTreeNode* t_rtn = dup_rtn(b_rtn, policy);
    update_rtn(sc, t_rtn, s);

    addRtnToOtn(sc, otn, t_rtn, ips_num);
}

RuleTreeNode* RuleStateMap::dup_rtn(RuleTreeNode* rtn, IpsPolicy* policy)
{
    RuleTreeNode* ret = new RuleTreeNode(*rtn);

    auto ipvt = policy ? policy->ip_vartable : nullptr;
    auto povt = policy ? policy->portVarTable : nullptr;

    auto sip = sfvt_lookup_var(ipvt, rtn->sip->name);
    auto dip = sfvt_lookup_var(ipvt, rtn->dip->name);
    auto spo = rtn->src_portobject
        ? PortVarTableFind(povt, rtn->src_portobject->name, false) : nullptr;
    auto dpo = rtn->dst_portobject
        ? PortVarTableFind(povt, rtn->dst_portobject->name, false) : nullptr;

    ret->sip = sip
        ? sfvar_create_alias(sip, sip->name)
        : sfvar_deep_copy(rtn->sip);
    if (!sip and rtn->sip->name)
        ret->sip->name = snort_strdup(rtn->sip->name);

    ret->dip = dip
        ? sfvar_create_alias(dip, dip->name)
        : sfvar_deep_copy(rtn->dip);
    if (!dip and rtn->dip->name)
        ret->dip->name = snort_strdup(rtn->dip->name);

    ret->src_portobject = spo ? spo : ret->src_portobject;
    ret->dst_portobject = dpo ? dpo : ret->dst_portobject;
    ret->otnRefCount = 0;

    if ( sip or dip or spo or dpo )
    {
        ret->rule_func = nullptr;
        parse_rule_process_rtn(ret);
        return ret;
    }

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

void RuleStateMap::update_rtn(SnortConfig* sc, RuleTreeNode* rtn, const RuleState& s)
{
    switch ( s.enable )
    {
    case IpsPolicy::DISABLED: rtn->clear_enabled(); break;
    case IpsPolicy::ENABLED: rtn->set_enabled(); break;
    case IpsPolicy::INHERIT_ENABLE: break;
    }

    ListHead* new_listhead = get_rule_list(sc, s.rule_action.c_str());

    if ( new_listhead and ( rtn->listhead != new_listhead ) )
        rtn->listhead = new_listhead;

    rtn->action = s.action;

    if ( rtn->header )
    {
        rtn->header = new RuleHeader(*rtn->header);
        rtn->header->action = s.rule_action;
    }
}

