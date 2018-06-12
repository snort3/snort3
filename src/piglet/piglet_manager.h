//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// piglet_manager.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_MANAGER_H
#define PIGLET_MANAGER_H

// Factory for instantiating piglet plugins

#include <string>
#include <vector>

namespace Lua
{
class State;
}

namespace Piglet
{
struct Chunk;
struct Api;
class BasePlugin;

class Manager
{
public:
    static void init();

    static void add_plugin(const Api*);

    static BasePlugin* instantiate(
        Lua::State&, const std::string&,
        std::string&, std::string&, bool = false);

    static void destroy(BasePlugin*);

    static void add_chunk(const std::string&, const std::string&, const std::string&);
    static const std::vector<Chunk>& get_chunks();
};
} // namespace Piglet

#endif

