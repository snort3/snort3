//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// plug_interface.h author Russ Combs <rucombs@cisco.com>

#ifndef PLUG_INTERFACE_H
#define PLUG_INTERFACE_H

// Plugin manager control point

namespace snort
{
    class Module;
    struct SnortConfig;
};

class PlugContext
{
public:
    virtual ~PlugContext() = default;
};

class PlugInterface
{
public:
    PlugInterface() { }
    virtual ~PlugInterface() = default;

    virtual void global_init() { }
    virtual void global_term() { }

    virtual void thread_init() { }
    virtual void thread_term() { }

    virtual void instantiate(snort::Module*, snort::SnortConfig*, const char* /*alias*/ = nullptr) { }

    virtual PlugContext* get_context() { return nullptr; }

private:
    friend class PluginManager;
    unsigned instantiated = 0;
};

#endif

