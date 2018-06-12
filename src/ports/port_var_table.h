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

// port_var_table.h derived from sfportobject.h by Marc Noron

#ifndef PORT_VAR_TABLE_H
#define PORT_VAR_TABLE_H

#include "hash/ghash.h"
#include "ports/port_object.h"
#include "ports/port_table.h"

//-------------------------------------------------------------------------
// PortVarTable
// port lists may be defined as 'name port-list'
// PortVars are internally stored in PortObjects
//-------------------------------------------------------------------------

typedef snort::GHash PortVarTable;

PortVarTable* PortVarTableCreate();
int PortVarTableFree(PortVarTable* pvt);
int PortVarTableAdd(PortVarTable* pvt, PortObject* po);
PortObject* PortVarTableFind(PortVarTable* pvt, const char* name);

#endif

