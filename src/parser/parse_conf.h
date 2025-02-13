//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <string>
#include "detection/rules.h"

void parse_conf_init();
void parse_conf_term();
void parse_conf_print();

namespace snort
{
struct SnortConfig;
}

const char* get_parse_file();

// returns code or nullptr if not found, file holds abs path
// file may hold original parse path on entry
const char* get_config_file(const char* arg, std::string& file);

void parse_rules_file(snort::SnortConfig*, const char* fname);
void parse_rules_string(snort::SnortConfig*, const char* str, bool ips_policy = true);

bool ParseIpVar(const char* name, const char* value);
void parse_include(snort::SnortConfig*, const char*);

void add_service_to_otn(snort::SnortConfig*, OptTreeNode*, const char*);

ListHead* get_rule_list(snort::SnortConfig*, const char*);

#endif

