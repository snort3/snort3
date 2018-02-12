//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/mpse_manager.h"
#include "utils/util.h"

void PortGroup::add_rule()
{
    rule_count++;
}

PortGroup* PortGroup::alloc()
{ return (PortGroup*)snort_calloc(sizeof(PortGroup)); }

void PortGroup::free(PortGroup* pg)
{
    pg->delete_nfp_rules();

    for (int i = PM_TYPE_PKT; i < PM_TYPE_MAX; i++)
    {
        if (pg->mpse[i] != nullptr)
        {
            MpseManager::delete_search_engine(pg->mpse[i]);
            pg->mpse[i] = nullptr;
        }
    }

    free_detection_option_root(&pg->nfp_tree);
    snort_free(pg);
}

bool PortGroup::add_nfp_rule(void* rd)
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

void PortGroup::delete_nfp_rules()
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

