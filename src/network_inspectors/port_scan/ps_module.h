//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// ps_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PS_MODULE_H
#define PS_MODULE_H

#include "framework/module.h"
#include "ps_detect.h"
#include "main/thread.h"

#define PS_NAME "port_scan"
#define PS_HELP "port scan inspector; also configure port_scan_global"

#define PSG_NAME "port_scan_global"
#define PSG_HELP "shared settings for port_scan inspectors for use with port_scan"

extern THREAD_LOCAL SimpleStats spstats;
extern THREAD_LOCAL ProfileStats psPerfStats;

//-------------------------------------------------------------------------

class PortScanGlobalModule : public Module
{
public:
    PortScanGlobalModule();
    ~PortScanGlobalModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;
    PsCommon* get_data();

private:
    PsCommon* common;
};

class PortScanModule : public Module
{
public:
    PortScanModule();
    ~PortScanModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    const RuleMap* get_rules() const override;

    unsigned get_gid() const override
    { return GID_PORT_SCAN; }

    PortscanConfig* get_data();

private:
    PortscanConfig* config;
};

#endif

