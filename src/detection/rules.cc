//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"
#include "hash/xhash.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"

#include "treenodes.h"

#ifdef REG_TEST
#define ParseError(...) ParseWarning(WARN_RULES, __VA_ARGS__)
#endif

using namespace snort;

void RuleState::apply(SnortConfig* sc)
{
    OptTreeNode* otn = OtnLookup(sc->otn_map, gid, sid);

    if ( otn == nullptr )
        ParseError("Rule state specified for invalid SID: %u GID: %u", sid, gid);
    else
    {
        if ( sc->global_rule_state )
        {
            for ( unsigned i = 0; i < sc->policy_map->ips_policy_count(); i++ )
            {
                if ( sc->policy_map->get_ips_policy(i) )
                    apply(sc, otn, i);
            }
        }
        else
            apply(sc, otn, policy);
    }
}

void RuleState::apply(SnortConfig* sc, OptTreeNode* otn, unsigned ips_num)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn, ips_num);
    
    if ( !rtn )
        return;

    if ( rtn->otnRefCount > 1 )
    {
        // duplicate to avoid blanket setting behavior of multiple OTNs
        rtn = find_updated_rtn(rtn, sc, ips_num);
        if ( !rtn )
        {
            rtn = dup_rtn(otn, sc, ips_num);
            replace_rtn(otn, rtn, sc, ips_num);
        }

        else if ( rtn != getRtnFromOtn(otn, ips_num) )
            replace_rtn(otn, rtn, sc, ips_num);

        update_rtn(getRtnFromOtn(otn, ips_num));
    }
    else
    {
        RuleTreeNode* existing_rtn = find_updated_rtn(rtn, sc, ips_num);

        // dedup to avoid wasting memory when transitioning RTN to behavior of existing one
        if ( existing_rtn )
            replace_rtn(otn, existing_rtn, sc, ips_num);
        else
            update_rtn(getRtnFromOtn(otn, ips_num));
    }
}

RuleTreeNode* RuleState::find_updated_rtn(RuleTreeNode* rtn, SnortConfig* sc, unsigned ips_num)
{
    RuleTreeNode test_rtn(*rtn);
    update_rtn(&test_rtn);

    RuleTreeNodeKey key { &test_rtn, ips_num };
    return (RuleTreeNode*)xhash_find(sc->rtn_hash_table, &key);
}

void RuleState::replace_rtn(OptTreeNode* otn, RuleTreeNode* replacement, SnortConfig* sc, unsigned ips_num)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn, ips_num);
    rtn->otnRefCount--;

    deleteRtnFromOtn(otn, ips_num, sc, rtn->otnRefCount == 0);
    addRtnToOtn(snort::SnortConfig::get_conf(), otn, replacement, ips_num);
}

RuleTreeNode* RuleState::dup_rtn(OptTreeNode* otn, SnortConfig* sc, unsigned ips_num)
{
    RuleTreeNode* rtn = getRtnFromOtn(otn, ips_num);
    RuleTreeNode* ret = new RuleTreeNode(*rtn);
    ret->otnRefCount = 1;
    
    auto ip_vartable = sc->policy_map->get_ips_policy(ips_num)->ip_vartable;

    if ( rtn->sip )
        ret->sip = sfvt_lookup_var(ip_vartable, rtn->sip->name);

    if ( rtn->dip )
        ret->dip = sfvt_lookup_var(ip_vartable, rtn->dip->name);

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

void RuleStateAction::update_rtn(RuleTreeNode* rtn)
{
    switch ( action )
    {
        case IpsPolicy::LOG: rtn->action = snort::Actions::Type::LOG; break;
        case IpsPolicy::PASS: rtn->action = snort::Actions::Type::PASS; break;
        case IpsPolicy::ALERT: rtn->action = snort::Actions::Type::ALERT; break;
        case IpsPolicy::DROP: rtn->action = snort::Actions::Type::DROP; break;
        case IpsPolicy::BLOCK: rtn->action = snort::Actions::Type::BLOCK; break;
        case IpsPolicy::RESET: rtn->action = snort::Actions::Type::RESET; break;
        case IpsPolicy::INHERIT_ACTION: break;
    }
}

void RuleStateEnable::update_rtn(RuleTreeNode* rtn)
{
    switch( enable )
    {
        case IpsPolicy::DISABLED: rtn->clear_enabled(); break;
        case IpsPolicy::ENABLED: rtn->set_enabled(); break;
        case IpsPolicy::INHERIT_ENABLE: break;
    }
}

