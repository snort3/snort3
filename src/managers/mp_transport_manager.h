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
// mp_transport_manager.h author Oleksandr Stepanov <ostepano@cisco.com>

#ifndef MP_TRANSPORT_MANAGER_H
#define MP_TRANSPORT_MANAGER_H

// Manager for multiprocess layer objects

#include <string>
#include "framework/mp_transport.h"

namespace snort
{
class Module;
struct SnortConfig;


//-------------------------------------------------------------------------

class MPTransportManager
{
public:
    static void instantiate(const MPTransportApi* api, Module* mod, SnortConfig*);
    static MPTransport* get_transport(const std::string& name);

    static void add_plugin(const MPTransportApi* api);

    static void thread_init();
    static void thread_term();

    static void term();
};
}
#endif

