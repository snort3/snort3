//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// s7comm_module.h author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifndef S7COMM_MODULE_H
#define S7COMM_MODULE_H

#include "framework/module.h"

#define GID_S7COMMPLUS 149

#define S7COMMPLUS_BAD_LENGTH        1
#define S7COMMPLUS_BAD_PROTO_ID      2
#define S7COMMPLUS_RESERVED_FUNCTION 3

#define S7COMMPLUS_NAME "s7commplus"
#define S7COMMPLUS_HELP "s7commplus inspection"

extern THREAD_LOCAL snort::ProfileStats s7commplus_prof;

class S7commplusModule : public snort::Module
{
public:
    S7commplusModule();

    unsigned get_gid() const override
    { return GID_S7COMMPLUS; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    { return &s7commplus_prof; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }
};

#endif

