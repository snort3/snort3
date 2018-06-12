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

// port_object2.h derived from sfportobject.h by Marc Noron

#ifndef PORT_OBJECT2_H
#define PORT_OBJECT2_H

#include "framework/bits.h"
#include "hash/ghash.h"
#include "utils/sflsq.h"

//-------------------------------------------------------------------------
// PortObject2 is similar to PortObject
//-------------------------------------------------------------------------


struct PortObject;

struct PortObject2
{
    // FIXIT-L convert char* to C++ string
    // prefix of this struct must match first 3 items in PortObject
    char* name;                 /* user name */
    int id;                     /* internal tracking - compiling sets this value */

    SF_LIST* item_list;         /* list of port and port-range items */
    snort::GHash* rule_hash;         /* hash of rule (rule-indexes) in use */

    PortBitSet* port_list;      /* for collecting ports that use this object */
    struct PortGroup* group;    /* PortGroup based on rule_hash  */

    int port_cnt;               /* count of ports using this object */
};

PortObject2* PortObject2New(int nrules /*guess at this */);
void PortObject2Free(PortObject2*);
void PortObject2Finalize(PortObject2*);
PortObject2* PortObject2Dup(PortObject*);

typedef void (*PortObjectIterator)(int port, void*);
void PortObject2Iterate(PortObject2*, PortObjectIterator, void*);

PortObject2* PortObject2AppendPortObject(PortObject2* poa, PortObject* pob);
PortObject2* PortObject2AppendPortObject2(PortObject2* poa, PortObject2* pob);
PortObject2* PortObjectAppendEx2(PortObject2* poa, PortObject* pob);

void PortObject2PrintPorts(PortObject2* po);
void PortObject2Print(PortObject2* po);
void PortObject2PrintEx(PortObject2* po,
    void (* print_index_map)(int index, char* buf, int bufsize) );

#endif

