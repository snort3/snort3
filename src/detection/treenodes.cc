//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "treenodes.h"

#include "framework/ips_option.h"
#include "utils/util.h"

OptFpList* AddOptFuncToList(RuleOptEvalFunc ro_eval_func, OptTreeNode* otn)
{
    OptFpList* ofp = (OptFpList*)snort_calloc(sizeof(OptFpList));
    ofp->OptTestFunc = ro_eval_func;

    if ( !otn->opt_func )
    {
        otn->opt_func = ofp;
    }
    else
    {
        OptFpList* tmp = otn->opt_func;

        // walk to the end of the list
        while ( tmp->next )
            tmp = tmp->next;

        tmp->next = ofp;
    }
    return ofp;
}

bool otn_set_agent(OptTreeNode* otn, snort::IpsOption* opt)
{
    if ( otn->agent )
        return false;

    otn->agent = opt;
    return true;
}

void otn_trigger_actions(const OptTreeNode* otn, snort::Packet* p)
{
    if ( otn->agent )
        otn->agent->action(p);
}

//-------------------------------------------------------------------------
// rule FOO
//-------------------------------------------------------------------------

void* get_rule_type_data(OptTreeNode* otn, const char* name)
{
    OptFpList* fpl = otn->opt_func;

    while ( fpl )
    {
        if ( fpl->ips_opt )
        {
            if ( !strcmp(fpl->ips_opt->get_name(), name) )
                return fpl->ips_opt;
        }
        fpl = fpl->next;
    }
    return nullptr;
}

namespace snort
{
bool otn_has_plugin(OptTreeNode* otn, const char* name)
{
    OptFpList* fpl = otn->opt_func;

    while ( fpl )
    {
        if ( !fpl->ips_opt )
            continue;

        if ( !strcmp(fpl->ips_opt->get_name(), name) )
            return true;

        fpl = fpl->next;
    }
    return false;
}
}
