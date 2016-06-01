//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "port_group.h"

#include <stdlib.h>
#include "utils/util.h"

void PortGroup::add_rule()
{
    rule_count++;
}

/*
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PortGroup.  This particular
**    function is specific in that it adds "no content" rules.
**    A "no content" rule is a snort rule that has no "content"
**    or "uri" flag, and hence does not need to be pattern
**    matched.
**
**    Each RULE_NODE in a PortGroup is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.
**
**  FORMAL INPUTS
**    PortGroup* - PortGroup to add the rule to.
**    void* - ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
bool PortGroup::add_nfp_rule(void* rd)
{
    if ( !nfp_head )
    {
        nfp_head = (RULE_NODE*)snort_calloc(sizeof(RULE_NODE));
        nfp_tail = nfp_head;
        nfp_head->rnNext = 0;
        nfp_head->rnRuleData = rd;
    }
    else
    {
        nfp_tail->rnNext = (RULE_NODE*)snort_calloc(sizeof(RULE_NODE));
        nfp_tail = nfp_tail->rnNext;
        nfp_tail->rnNext = 0;
        nfp_tail->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
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

