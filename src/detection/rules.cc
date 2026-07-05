//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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
#include <cinttypes>
#include <utility>

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
    IpsPolicy* target_policy = sc->policy_map->get_ips_policy(ips_num);
    IpsPolicy* clone_policy = nullptr;
    RuleTreeNode* b_rtn = getRtnFromOtn(otn, ips_num);

    if ( !b_rtn and ips_num and (b_rtn = getRtnFromOtn(otn, 0)) )
        clone_policy = target_policy;

    if ( !b_rtn )
        return;

    RuleTreeNode* t_rtn = dup_rtn(b_rtn, clone_policy);
    if ( !update_rtn(sc, target_policy, t_rtn, s) )
    {
        DestroyRuleTreeNode(t_rtn);
        return;
    }

    if ( clone_policy )
        clone_policy->rules_shared++;

    addRtnToOtn(sc, otn, t_rtn, ips_num);
}

RuleTreeNode* RuleStateMap::dup_rtn(RuleTreeNode* rtn, IpsPolicy* policy)
{
    RuleTreeNode* ret = new RuleTreeNode(*rtn);
    if ( ret->header )
        ret->header = new RuleHeader(*ret->header);

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

bool RuleStateMap::update_rtn(SnortConfig* sc, IpsPolicy* policy, RuleTreeNode* rtn,
    const RuleState& s)
{
    std::string rule_action = s.rule_action;
    uint8_t action = s.action;
    IpsPolicy::ActionSelector action_selector = s.action_selector;

    if ( !rule_action.empty() and rule_action[0] == '$' )
    {
        if ( !policy )
        {
            ParseError("unknown IPS action variable '%s'", rule_action.c_str());
            return false;
        }

        const std::string* action_name = nullptr;
        if ( !policy->get_action_variable(rule_action.c_str() + 1,
            action_name, action, action_selector) )
        {
            ParseError("unknown IPS action variable '%s' in IPS policy %" PRIu64,
                rule_action.c_str(), policy->user_policy_id);
            return false;
        }

        rule_action = *action_name;
    }

    switch ( s.enable )
    {
    case IpsPolicy::DISABLED: rtn->clear_enabled(); break;
    case IpsPolicy::ENABLED: rtn->set_enabled(); break;
    case IpsPolicy::INHERIT_ENABLE: break;
    }

    ListHead* new_listhead = get_rule_list(sc, rule_action.c_str());

    if ( new_listhead and ( rtn->listhead != new_listhead ) )
        rtn->listhead = new_listhead;

    rtn->action = action;
    rtn->action_selector = action_selector;

    if ( rtn->header )
        rtn->header->action = std::move(rule_action);

    return true;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

#include <memory>

#include "catch/snort_catch.h"
#include "log/log_errors.h"

struct RuleTreeNodeTestCleanup
{
    explicit RuleTreeNodeTestCleanup(RuleTreeNode& node) : rtn(node) { }
    ~RuleTreeNodeTestCleanup() { FreeRuleTreeNode(&rtn); }

    RuleTreeNodeTestCleanup(const RuleTreeNodeTestCleanup&) = delete;
    RuleTreeNodeTestCleanup& operator=(const RuleTreeNodeTestCleanup&) = delete;

    RuleTreeNode& rtn;
};

struct RuleTreeNodeTestDeleter
{
    void operator()(RuleTreeNode* rtn) const
    {
        if ( rtn )
            DestroyRuleTreeNode(rtn);
    }
};

struct RuleStateMapTestAccess
{
    static RuleTreeNode* dup_rtn(RuleStateMap& states, RuleTreeNode* rtn, IpsPolicy* policy)
    { return states.dup_rtn(rtn, policy); }

    static bool update_rtn(RuleStateMap& states, SnortConfig* sc, IpsPolicy* policy,
        RuleTreeNode* rtn, const RuleState& state)
    { return states.update_rtn(sc, policy, rtn, state); }
};

TEST_CASE("RuleStateMap update_rtn rejects action variable without policy", "[RuleStateMap]")
{
    reset_parse_errors();

    RuleStateMap states;
    RuleTreeNode rtn;
    RuleState state =
    {
        "$REACT_RULE_PAGE",
        0,
        0,
        IpsPolicy::ENABLED
    };

    const bool updated = RuleStateMapTestAccess::update_rtn(states, nullptr, nullptr, &rtn, state);
    CHECK(!updated);
    CHECK(get_parse_errors() == 1);
}

TEST_CASE("RuleStateMap failed update cleanup keeps source RTN header", "[RuleStateMap]")
{
    reset_parse_errors();

    std::unique_ptr<vartable_t, decltype(&sfvt_free_table)> table(
        sfvt_alloc_table(), sfvt_free_table);
    REQUIRE(table);

    sfip_var_t* var = nullptr;
    REQUIRE(sfvt_add_str(table.get(), "test_net [any]", &var) == SFIP_SUCCESS);

    RuleTreeNode source;
    RuleTreeNodeTestCleanup source_cleanup(source);
    source.sip = sfvar_deep_copy(var);
    source.dip = sfvar_deep_copy(var);
    source.header = new RuleHeader("alert");
    REQUIRE(source.sip);
    REQUIRE(source.dip);

    RuleStateMap states;
    RuleTreeNode* clone = RuleStateMapTestAccess::dup_rtn(states, &source, nullptr);
    REQUIRE(clone);

    const bool clone_owns_header = clone->header != source.header;
    CHECK(clone_owns_header);
    if ( !clone_owns_header )
    {
        clone->header = nullptr;
        DestroyRuleTreeNode(clone);
        return;
    }

    std::unique_ptr<RuleTreeNode, RuleTreeNodeTestDeleter> clone_cleanup(clone);

    RuleState state =
    {
        "$REACT_RULE_PAGE",
        0,
        0,
        IpsPolicy::ENABLED
    };

    const bool updated = RuleStateMapTestAccess::update_rtn(states, nullptr, nullptr, clone, state);
    CHECK(!updated);
    CHECK(get_parse_errors() == 1);

    clone_cleanup.reset();
    CHECK(source.header->action == "alert");
}

#endif
