//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// packet_tracer_module.h author Shashikant Lad <shaslad@cisco.com>

#ifndef PACKET_TRACER_MODULE_H
#define PACKET_TRACER_MODULE_H

#include "framework/module.h"

#define PACKET_TRACER_NAME "packet_tracer"
#define PACKET_TRACER_HELP "generate debug trace messages for packets"

struct PacketTracerConfig
{
    bool enabled;
    std::string file;
};

class PacketTracerModule : public snort::Module
{
public:
    PacketTracerModule();


    enum PacketTraceOutput
    {
        PACKET_TRACE_CONSOLE,
        PACKET_TRACE_FILE
    };

    const snort::Command* get_commands() const override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    PacketTracerConfig* config = nullptr;
};

#endif
