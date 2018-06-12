//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// port_table.h derived from sfportobject.h by Marc Noron

#ifndef PORT_TABLE_H
#define PORT_TABLE_H

#include "hash/ghash.h"
#include "ports/port_item.h"
#include "ports/port_object.h"
#include "ports/port_object2.h"
#include "utils/sflsq.h"

//-------------------------------------------------------------------------
// PortTable - provides support to analyze the Port List objects defined by
// the user as either PortVar entries or simply as inline rule port list
// declarations.
//-------------------------------------------------------------------------

struct PortTable
{
    /* turns on group optimization, better speed-but more memory
     * otherwise a single merged rule group is used.
     */
    int pt_optimize;

    /* save the users input port objects in this list
     * rules may be added after creation of a port object
     * but the ports are not modified.
     */
    SF_LIST* pt_polist;
    int pt_poid;

    /* Compiled / merged port object hash table */
    snort::GHash* pt_mpo_hash;
    snort::GHash* pt_mpxo_hash;

    /*
    * Final Port/Rule Groupings, one port object per port, or null
    */
    PortObject2* pt_port_object[SFPO_MAX_PORTS];

    int pt_lrc; /* large rule count, this many rules is a large group */

    /* Stats */
    int single_merges; /* single PortObject on a port */
    int small_merges;  /* small port objects merged into a bigger object */
    int large_single_merges; /* 1 large + some small objects */
    int large_multi_merges; /* >1 large object merged + some small objects */
    int non_opt_merges;
};

PortTable* PortTableNew();
void PortTableFree(PortTable*);
void PortTableFinalize(PortTable*);

PortObject* PortTableFindInputPortObjectPorts(PortTable*, PortObject*);

int PortTableAddObject(PortTable*, PortObject*);
int PortTableCompile(PortTable*);

typedef void (* rim_print_f)(int index, char* buf, int bufsize);

void PortTablePrintInputEx(PortTable*, rim_print_f);
int PortTablePrintCompiledEx(PortTable*, rim_print_f);

void PortTablePrintInput(PortTable*);
void PortTablePrintUserRules(PortTable*);
void PortTablePrintPortGroups(PortTable*);

void RuleListSortUniq(SF_LIST*);
void PortTableSortUniqRules(PortTable*);

#endif

