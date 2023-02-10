//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "port_var_table.h"

#include "hash/ghash.h"
#include "hash/hash_defs.h"
#include "main/snort_config.h"
#include "utils/util.h"

using namespace snort;

//-------------------------------------------------------------------------
// PortVarTable
//-------------------------------------------------------------------------

/*
*  Create a PortVar Table
*
*  The PortVar table used to store and lookup Named PortObjects
*/
PortVarTable* PortVarTableCreate()
{
    /*
     * This is used during parsing of config,
     * so 1000 entries is ok, worst that happens is somewhat slower
     * config/rule processing.
     */
    GHash* h = new GHash(1000, 0, false, PortObjectFree);
    PortObject* po = PortObjectNew();       // Create default port objects
    PortObjectAddPortAny(po);   // Default has an ANY port
    PortVarTableAdd(h, po);     // Add ANY to the table

    return h;
}

/*
    This deletes the table, the PortObjects and PortObjectItems,
    and rule list.
*/
int PortVarTableFree(PortVarTable* pvt)
{
    if ( pvt )
        delete pvt;

    return 0;
}

/*
*   PortVarTableAdd()
*
*   returns
*       -1 : error, no memory...
*        0 : added
*        1 : in table
*/
int PortVarTableAdd(PortVarTable* h, PortObject* po)
{
    int stat = h->insert(po->name, po);
    if ( stat == HASH_INTABLE )
        return 1;

    if ( stat == HASH_OK )
        return 0;

    return -1;
}

PortObject* PortVarTableFind(PortVarTable* h, const char* name, bool add_if_not_found)
{
    if (!h || !name)
        return nullptr;

    PortObject* po = (PortObject*)h->find(name);

    if ( !po and SnortConfig::get_conf()->dump_rule_info() and add_if_not_found )
    {
        po = PortObjectNew();
        po->name = snort_strdup(name);
        PortVarTableAdd(h, po);
    }
    return po;
}

