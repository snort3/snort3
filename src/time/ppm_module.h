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
// ppm_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PPM_MODULE_H
#define PPM_MODULE_H

// Configuration module for packet performance monitoring

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// FIXIT-M: Instead of an empty source file, use CMake/Make to enable/disable
//          this compilation unit
#ifdef PPM_MGR
#include "framework/module.h"

#define GID_PPM 134

// SIDs
#define PPM_EVENT_RULE_TREE_DISABLED 1
#define PPM_EVENT_RULE_TREE_ENABLED  2
#define PPM_EVENT_PACKET_ABORTED     3

class PpmModule : public Module
{
public:
    PpmModule();

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    const RuleMap* get_rules() const override;

    unsigned get_gid() const override
    { return GID_PPM; }
};

#endif // PPM_MGR
#endif

