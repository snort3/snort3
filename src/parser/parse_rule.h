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

#ifndef PARSE_RULE_H
#define PARSE_RULE_H

#include "detection/rules.h"
#include "framework/ips_option.h"

namespace snort
{
struct SnortConfig;
}
struct OptFpList;
struct OptTreeNode;
struct RuleTreeNode;

void parse_rule_init();
void parse_rule_term();
void parse_rule_print();

void parse_rule_type(snort::SnortConfig*, const char*, RuleTreeNode&);
void parse_rule_proto(snort::SnortConfig*, const char*, RuleTreeNode&);
void parse_rule_nets(snort::SnortConfig*, const char*, bool src, RuleTreeNode&);
void parse_rule_ports(snort::SnortConfig*, const char*, bool src, RuleTreeNode&);
void parse_rule_dir(snort::SnortConfig*, const char*, RuleTreeNode&);
void parse_rule_opt_begin(snort::SnortConfig*, const char* key);
void parse_rule_opt_set(
    snort::SnortConfig*, const char* key, const char* opt, const char* val);
void parse_rule_opt_end(snort::SnortConfig*, const char* key, OptTreeNode*);
OptTreeNode* parse_rule_open(snort::SnortConfig*, RuleTreeNode&, bool stub = false);
const char* parse_rule_close(snort::SnortConfig*, RuleTreeNode&, OptTreeNode*);

int get_rule_count();

#endif

