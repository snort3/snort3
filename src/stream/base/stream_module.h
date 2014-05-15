/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// stream_module.h author Russ Combs <rucombs@cisco.com>

#ifndef STREAM_MODULE_H
#define STREAM_MODULE_H

#include "snort_types.h"
#include "framework/module.h"
#include "flow/flow_control.h"

struct SnortConfig;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

#define MOD_NAME "stream"

struct StreamConfig
{
    FlowConfig ip_cfg;
    FlowConfig icmp_cfg;
    FlowConfig tcp_cfg;
    FlowConfig udp_cfg;
};

class StreamModule : public Module
{
public:
    StreamModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

    const StreamConfig* get_data();

private:
    FlowConfig& proto;
};

#endif

