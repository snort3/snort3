//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

#include "port_group.h"

#include "detection/detection_options.h"
#include "framework/ips_option.h"
#include "framework/mpse.h"
#include "utils/util.h"

void RuleGroup::add_rule()
{
    rule_count++;
}

RuleGroup::~RuleGroup()
{
    for ( int sect = snort::PS_NONE; sect <= snort::PS_MAX; sect++)
        for ( const auto* it : pm_list[sect] )
            delete it;

    delete_nfp_rules();
    free_detection_option_root(&nfp_tree);
}

bool RuleGroup::add_nfp_rule(void* rd)
{
    if ( !nfp_head )
    {
        nfp_head = (RULE_NODE*)snort_alloc(sizeof(RULE_NODE));
        nfp_tail = nfp_head;
        nfp_head->rnNext = nullptr;
    }
    else
    {
        nfp_tail->rnNext = (RULE_NODE*)snort_alloc(sizeof(RULE_NODE));
        nfp_tail = nfp_tail->rnNext;
        nfp_tail->rnNext = nullptr;
    }

    nfp_tail->rnRuleData = rd;
    nfp_tail->iRuleNodeID = rule_count;

    nfp_rule_count++;
    rule_count++;

    return true;
}

void RuleGroup::delete_nfp_rules()
{
    RULE_NODE* rn = nfp_head;

    while (rn)
    {
        RULE_NODE* tmpRn = rn->rnNext;
        snort_free(rn);
        rn = tmpRn;
    }
    nfp_head = nullptr;
}

PatternMatcher* RuleGroup::get_pattern_matcher(PatternMatcher::Type t, const char* s, snort::PduSection sect)
{
    bool raw = false;

    if ( !strcmp(s, "raw_data") )
    {
        s = "pkt_data";
        raw = true;
    }
    for ( auto& it : pm_list[sect] )
    {
        if ( it->type == t and !strcmp(it->name, s) )
        {
            it->raw_data = raw;
            return it;
        }
    }
    pm_list[sect].push_back(new PatternMatcher(t, s, raw));
    return pm_list[sect].back();
}

