/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef VARS_H
#define VARS_H

#include "main/snort_config.h"
#include "sfip/sf_vartable.h"

//-------------------------------------------------------------------------
// var node stuff
//-------------------------------------------------------------------------

struct VarNode
{
    char *name;
    char *value;
    char *line;
    VarNode *next;
};

void config_set_var(SnortConfig* sc, const char*);
void FreeVarList(VarNode*);

//-------------------------------------------------------------------------
// var table stuff
//-------------------------------------------------------------------------

void InitVarTables(IpsPolicy*);
void VarTablesFree(IpsPolicy*);

VarEntry * VarDefine(SnortConfig *sc, const char *name, const char *value);
int PortVarDefine(SnortConfig *sc, const char *name, const char *s);
void ParseIpVar(SnortConfig *sc, const char *name, const char *s);  // FIXIT-L actually in parse_conf.cc

VarEntry *VarAlloc();
void DeleteVars(VarEntry *var_table);
void AddVarToTable(SnortConfig *, const char *, const char *);

enum VarType
{
    VAR_TYPE__DEFAULT,
    VAR_TYPE__PORTVAR,
    VAR_TYPE__IPVAR

};

int VarIsIpAddr(vartable_t *ip_vartable, const char *value);
int VarIsIpList(vartable_t *ip_vartable, const char *value);
void DisallowCrossTableDuplicateVars(SnortConfig *sc, const char *name, VarType var_type);
const char *VarGet(SnortConfig *sc, const char *name);
/*
 * Same as VarGet - but this does not Fatal out if a var is not found
 */
const char * VarSearch(SnortConfig *sc, const char *name);

const char * ExpandVars(SnortConfig *sc, const char *string);

#endif

