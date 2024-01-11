//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// mms_module.h author Jared Rittle <jared.rittle@cisco.com>
// modeled after modbus_module.h (author Russ Combs <rucombs@cisco.com>)
// modeled after s7comm_module.h (author Pradeep Damodharan <prdamodh@cisco.com>)

#ifndef MMS_MODULE_H
#define MMS_MODULE_H

// MMS Module defines everything needed to integrate the MMS service
// inspector into the framework

#include "framework/module.h"

#define GID_MMS     152

#define MMS_NAME    "mms"
#define MMS_HELP    "mms inspection"

extern THREAD_LOCAL snort::ProfileStats mms_prof;

class MmsModule : public snort::Module
{
public:
    MmsModule();

    unsigned get_gid() const override
    {
        return GID_MMS;
    }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    {
        return &mms_prof;
    }

    Usage get_usage() const override
    {
        return INSPECT;
    }

    bool is_bindable() const override
    {
        return true;
    }
};

#endif

