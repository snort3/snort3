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

#include <cassert>

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
        rtn = getRtnFromOtn(otn, 0);

    if ( !rtn )
        return;

    rtn = dup_rtn(rtn);
    update_rtn(rtn);
    addRtnToOtn(sc, otn, rtn, ips_num);
}

RuleTreeNode* RuleState::dup_rtn(RuleTreeNode* rtn)
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

void RuleState::update_rtn(RuleTreeNode* rtn)
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
    switch ( enable )
    {
        case IpsPolicy::DISABLED: rtn->clear_enabled(); break;
        case IpsPolicy::ENABLED: rtn->set_enabled(); break;
        case IpsPolicy::INHERIT_ENABLE: break;
    }
}

