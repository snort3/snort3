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
// pp_event_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_event_iface.h"

#include <cstring>

#include "detection/signature.h"
#include "events/event.h"
#include "lua/lua_arg.h"

#include "pp_raw_buffer_iface.h"

static struct SigInfo* create_sig_info()
{
    auto si = new SigInfo;
    memset(si, 0, sizeof(SigInfo));
    return si;
}

static void set_fields(lua_State* L, int tindex, Event& self)
{
    Lua::Table table(L, tindex);

    table.get_field("event_id", self.event_id);
    table.get_field("event_reference", self.event_reference);

    const char* s = nullptr;
    if ( table.get_field("alt_msg", s) && s )  // FIXIT-L shouldn't need both conditions
    {
        self.alt_msg = RawBufferIface.create(L, s).c_str();
        Lua::add_ref(L, &self, "alt_msg", lua_gettop(L));
        lua_pop(L, 1);
    }
}

static void get_fields(lua_State* L, int tindex, Event& self)
{
    Lua::Table table(L, tindex);

    table.set_field("event_id", self.event_id);
    table.set_field("event_reference", self.event_reference);

    if ( self.alt_msg )
        table.set_field("alt_msg", self.alt_msg);
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = EventIface.create(L);
            // FIXIT-M SigInfo should be a separate object
            // (to make resource tracking more uniform)
            self.sig_info = create_sig_info();

            args[1].opt_table(set_fields, self);

            return 1;
        }
    },
    {
        "get",
        // FIXIT-L add support for getting strings
        [](lua_State* L)
        {
            auto& self = EventIface.get(L);
            lua_newtable(L);

            get_fields(L, lua_gettop(L), self);

            auto si = self.sig_info;

            if ( si )
            {
                Lua::ManageStack ms(L);
                lua_newtable(L);
                Lua::Table si_table(L, lua_gettop(L));

                si_table.set_field("generator", si->gid);
                si_table.set_field("id", si->sid);
                si_table.set_field("rev", si->rev);
                si_table.set_field("class_id", si->class_id);
                si_table.set_field("priority", si->priority);
                si_table.set_field("builtin", si->builtin);
                si_table.set_field("num_services", si->num_services);

                Lua::Table(L, 2).set_field_from_stack("sig_info", si_table.index);
            }

            return 1;
        }
    },
    {
        "set",
        // FIXIT-L add support for setting strings
        [](lua_State* L)
        {
            auto& self = EventIface.get(L);
            luaL_checktype(L, 2, LUA_TTABLE);

            Lua::Table table(L, 2);
            table.get_field_to_stack("sig_info");

            auto* si = const_cast<SigInfo*>(self.sig_info);

            if ( si && lua_istable(L, lua_gettop(L)) )
            {
                Lua::ManageStack ms(L);
                Lua::Table si_table(L, lua_gettop(L));

                si_table.get_field("generator", si->gid);
                si_table.get_field("id", si->sid);
                si_table.get_field("rev", si->rev);
                si_table.get_field("class_id", si->class_id);
                si_table.get_field("priority", si->priority);
                si_table.get_field("builtin", si->builtin);
                si_table.get_field("num_services", si->num_services);
            }

            set_fields(L, 2, self);

            return 0;
        }
    },
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return EventIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            auto** t = EventIface.regurgitate(L);
            delete (*t)->sig_info;
            EventIface.destroy(L, t);

            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Event> EventIface =
{
    "Event",
    methods,
    metamethods
};
