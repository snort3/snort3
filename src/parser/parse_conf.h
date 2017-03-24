//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifndef PARSE_CONF_H
#define PARSE_CONF_H

#include "detection/rules.h"

void parse_conf_init();
void parse_conf_term();
void parse_conf_print();

struct SnortConfig;

void ParseConfigFile(SnortConfig*, const char* fname);
void ParseConfigString(SnortConfig*, const char* str);

void parse_include(SnortConfig*, const char*);

void AddRuleState(SnortConfig*, const RuleState&);
void add_service_to_otn(SnortConfig*, OptTreeNode*, const char*);

RuleType get_rule_type(const char*);
ListHead* get_rule_list(SnortConfig*, const char*);

#endif

