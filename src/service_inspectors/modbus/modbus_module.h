//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// modbus_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef MODUBS_MODULE_H
#define MODUBS_MODULE_H

#include "framework/module.h"

#define GID_MODBUS 144

#define MODBUS_BAD_LENGTH        1
#define MODBUS_BAD_PROTO_ID      2
#define MODBUS_RESERVED_FUNCTION 3

#define MODBUS_NAME "modbus"
#define MODBUS_HELP "modbus inspection"

extern THREAD_LOCAL snort::ProfileStats modbus_prof;

class ModbusModule : public snort::Module
{
public:
    ModbusModule();

    unsigned get_gid() const override
    { return GID_MODBUS; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    { return &modbus_prof; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }
};

#endif

