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

// sfrim.h author Marc Norton

#ifndef SFRIM_H
#define SFRIM_H

// provides an ordinal for each rule so they can be looked up by a number
// used during parse time when rules are compiled

struct rule_index_map_t;

rule_index_map_t* RuleIndexMapCreate();
void RuleIndexMapFree(rule_index_map_t*);

int RuleIndexMapAdd(rule_index_map_t*, unsigned gid, unsigned sid);
bool RuleIndexMapGet(rule_index_map_t* map, int index, unsigned& gid, unsigned& sid);

#endif

