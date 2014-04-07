/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

// ps_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PS_MODULE_H
#define PS_MODULE_H

#include "framework/module.h"
#include "ps_detect.h"

#define PS_MODULE "port_scan"
#define PS_GLOBAL "port_scan_global"

//-------------------------------------------------------------------------

class PortScanGlobalModule : public Module
{
public:
    PortScanGlobalModule();
    ~PortScanGlobalModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

    PsCommon* get_data();

private:
    PsCommon* common;
};

class PortScanModule : public Module
{
public:
    PortScanModule();
    ~PortScanModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

    unsigned get_gid() const
    { return GID_PORT_SCAN; };

    PortscanConfig* get_data();

private:
    PortscanConfig* config;
};

#endif

