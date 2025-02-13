//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// network_module.cc author Ron Dempster <rdempste@cisco.com>

#ifndef NETWORK_MODULE_H
#define NETWORK_MODULE_H

#include "framework/module.h"


class NetworkModule : public snort::Module
{
public:
    NetworkModule();
    ~NetworkModule() override = default;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const snort::Command* get_commands() const override;

    Usage get_usage() const override
    { return CONTEXT; }
};

#endif
