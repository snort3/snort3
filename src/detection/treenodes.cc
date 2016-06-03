//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "treenodes.h"

#include "framework/ips_option.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#include "detect.h"

/****************************************************************************
 *
 * Function: AddOptFuncToList(int (*func)(), OptTreeNode *)
 *
 * Purpose: Links the option detection module to the OTN
 *
 * Arguments: (*func)() => function pointer to the detection module
 *            otn =>  pointer to the current OptTreeNode
 *
 * Returns: void function
 *
 ***************************************************************************/
OptFpList* AddOptFuncToList(RuleOptEvalFunc ro_eval_func, OptTreeNode* otn)
{
    OptFpList* ofp = (OptFpList*)snort_calloc(sizeof(OptFpList));

    DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n");

    /* if there are no nodes on the function list... */
    if (otn->opt_func == NULL)
    {
        otn->opt_func = ofp;
    }
    else
    {
        OptFpList* tmp = otn->opt_func;

        /* walk to the end of the list */
        while ( tmp->next )
            tmp = tmp->next;

        tmp->next = ofp;
    }

    DebugFormat(DEBUG_CONFIGRULES,"Set OptTestFunc to %p\n", (void*)ro_eval_func);

    ofp->OptTestFunc = ro_eval_func;

    return ofp;
}

bool otn_set_agent(OptTreeNode* otn, IpsOption* opt)
{
    if ( otn->agent )
        return false;

    otn->agent = opt;
    return true;
}

void otn_trigger_actions(const OptTreeNode* otn, Packet* p)
{
    if ( otn->agent )
        otn->agent->action(p);
}

//-------------------------------------------------------------------------
// rule FOO
//-------------------------------------------------------------------------

void* get_rule_type_data(OptTreeNode* otn, option_type_t type)
{
    OptFpList* fpl = otn->opt_func;

    while ( fpl )
    {
        if ( fpl->type == type )
            return fpl->ips_opt;

        fpl = fpl->next;
    }
    return nullptr;
}

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

