//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef ACTIONS_H
#define ACTIONS_H

#include <stdint.h>

#define ACTION_ALERT    "alert"
#define ACTION_DROP     "drop"
#define ACTION_BLOCK    "block"
#define ACTION_LOG      "log"
#define ACTION_PASS     "pass"
#define ACTION_SDROP    "sdrop"
#define ACTION_SBLOCK   "sblock"

enum RuleType
{
    RULE_TYPE__NONE = 0,
    RULE_TYPE__ALERT,
    RULE_TYPE__DROP,
    RULE_TYPE__LOG,
    RULE_TYPE__PASS,
    RULE_TYPE__SDROP,
    RULE_TYPE__MAX
};

const char* get_action_string(int action);
RuleType get_action_type(const char*);
void action_execute(int action, struct Packet*, struct OptTreeNode*, uint16_t event_id);

static inline bool pass_action(int a)
{
    return ( a == RULE_TYPE__PASS );
}

static inline bool block_action(int a)
{
    return ( (a == RULE_TYPE__DROP) ||
           (a == RULE_TYPE__SDROP) );
}

int AlertAction(Packet*, const OptTreeNode*);

#endif

