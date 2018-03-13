//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef VARS_H
#define VARS_H

#include <cstdint>

#include "sfip/sf_vartable.h"

namespace snort
{
struct SnortConfig;
}

//-------------------------------------------------------------------------
// var node stuff
//-------------------------------------------------------------------------

struct VarNode
{
    char* name;
    char* value;
    char* line;
    VarNode* next;
};

void config_set_var(snort::SnortConfig*, const char*);
void FreeVarList(VarNode*);

//-------------------------------------------------------------------------
// var table stuff
//-------------------------------------------------------------------------

struct VarEntry
{
    char* name;
    char* value;

    unsigned char flags;
    uint32_t id;

    sfip_var_t* addrset;
    VarEntry* prev;
    VarEntry* next;
};

VarEntry* VarDefine(snort::SnortConfig*, const char* name, const char* value);
int PortVarDefine(snort::SnortConfig*, const char* name, const char* s);

// FIXIT-L put ParseIpVar() definition and declaration in matching files
void ParseIpVar(snort::SnortConfig*, const char* name, const char* s);

VarEntry* VarAlloc();
void DeleteVars(VarEntry* var_table);
void AddVarToTable(snort::SnortConfig*, const char*, const char*);

enum VarType
{
    VAR_TYPE__DEFAULT,
    VAR_TYPE__PORTVAR,
    VAR_TYPE__IPVAR
};

int VarIsIpAddr(vartable_t* ip_vartable, const char* value);
int VarIsIpList(vartable_t* ip_vartable, const char* value);
void DisallowCrossTableDuplicateVars(snort::SnortConfig*, const char* name, VarType var_type);

const char* VarSearch(snort::SnortConfig*, const char* name);
const char* ExpandVars(snort::SnortConfig*, const char* string);

#endif

