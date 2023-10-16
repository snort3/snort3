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

// port_object.h derived from sfportobject.h by Marc Noron

#ifndef PORT_OBJECT_H
#define PORT_OBJECT_H

#include "utils/sflsq.h"

//-------------------------------------------------------------------------
// PortObject supports a set of PortObjectItems
// associates rules with a RuleGroup.
//-------------------------------------------------------------------------

struct RuleGroup;
struct PortObjectItem;

struct PortObject
{
    // FIXIT-L convert char* to C++ string
    char* name;                 /* user name */
    int id;                     /* internal tracking - compiling sets this value */
    mutable unsigned hash = 0;

    SF_LIST* item_list;         /* list of port and port-range items */
    SF_LIST* rule_list;         /* list of rules  */

    RuleGroup* group;           // based on rule_list - only used by any-any ports
};

PortObject* PortObjectNew();
void PortObjectFree(void*);
void PortObjectFinalize(PortObject*);

int PortObjectSetName(PortObject*, const char* name);
int PortObjectAddItem(PortObject*, PortObjectItem*, int* errflag);
int PortObjectAddPortObject(PortObject* podst, PortObject* posrc, int* errflag);
int PortObjectAddPort(PortObject*, int port);
int PortObjectAddRange(PortObject*, int lport, int hport);
int PortObjectAddRule(PortObject*, int rule);
int PortObjectAddPortAny(PortObject*);

PortObject* PortObjectDup(PortObject*);
PortObject* PortObjectDupPorts(PortObject*);

int PortObjectNormalize(PortObject*);
void PortObjectToggle(PortObject*);
bool PortObjectEqual(PortObject* poa, PortObject* pob);

int PortObjectPortCount(PortObject*);
int PortObjectHasPort(PortObject*, int port);
int PortObjectIsPureNot(PortObject*);
int PortObjectHasAny(PortObject*);

int PortObjectRemovePorts(PortObject* a,  PortObject* b);
PortObject* PortObjectAppend(PortObject* poa, PortObject* pob);

void PortObjectPrint(PortObject*);
void PortObjectPrintPortsRaw(PortObject*);

typedef void (*po_print_f)(int index, char* buf, int bufsize);
void PortObjectPrintEx(PortObject*, po_print_f);

unsigned PortObjectHash(const PortObject*, unsigned hash, unsigned scale, unsigned hardener);

#endif

