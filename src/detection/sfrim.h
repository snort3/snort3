//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

/*
 *   Rule Index Map
 *
 *   author: marc norton
 */
#ifndef SFRIM_H
#define SFRIM_H

typedef struct
{
    unsigned gid;
    unsigned sid;
}rule_number_t;

typedef struct
{
    int max_rules;
    int num_rules;
    rule_number_t* map;
}rule_index_map_t;

unsigned RuleIndexMapSid(rule_index_map_t* map, int index);
unsigned RuleIndexMapGid(rule_index_map_t* map, int index);
rule_index_map_t* RuleIndexMapCreate(int max_rules);
void RuleIndexMapFree(rule_index_map_t** p);
int RuleIndexMapAdd(rule_index_map_t* p, unsigned gid, unsigned sid);

#endif

