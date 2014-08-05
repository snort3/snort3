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

#ifndef PARSE_CONF_H
#define PARSE_CONF_H

#include "detection/rules.h"

void parse_conf_init();
void parse_conf_term();
void parse_conf_print();

struct SnortConfig;

void ParseConfigFile(SnortConfig*, const char* fname, bool do_rules);
void ParseConfigString(SnortConfig*, const char* str, bool do_rules);

void AddRuleState(SnortConfig*, const RuleState&);

#define ERR_PAIR_COUNT \
        "%s has incorrect argument count; should be %d pairs.", ERR_KEY
#define ERR_NOT_PAIRED \
        "%s is missing an option or argument to go with: %s.", ERR_KEY, pairs[0]
#define ERR_EXTRA_OPTION \
        "%s has extra option of type: %s.", ERR_KEY, pairs[0]
#define ERR_BAD_OPTION \
        "%s has unknown option: %s.", ERR_KEY, pairs[0]
#define ERR_BAD_VALUE \
        "%s has unknown %s: %s.", ERR_KEY, pairs[0], pairs[1]
#define ERR_BAD_ARG_COUNT \
        "%s has incorrect argument count.", ERR_KEY
#define ERR_CREATE \
        "%s could not be created.", ERR_KEY
#define ERR_CREATE_EX \
        "%s could not be created: %s.", ERR_KEY

#endif

