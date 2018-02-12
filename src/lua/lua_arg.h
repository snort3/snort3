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
// lua_arg.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_ARG_H
#define LUA_ARG_H

#include "lua_stack.h"

namespace Lua
{
class Args
{
public:
    template<typename T>
    using ArgCallback = void (*)(lua_State*, int, T& ud);

    Args(lua_State* state) : L { state }, count { lua_gettop(L) } { }

private:
    lua_State* L;

    struct ArgRef
    {
    public:
        ArgRef(lua_State* state, int ct, int i) :
            L { state }, count { ct }, index { i } { }

        // We treat nil as !exists
        inline bool exists()
        { return (index > 0) && (index <= count) && !lua_isnoneornil(L, index); }

        inline bool is_table()
        { return exists() && lua_istable(L, index); }

        inline void check_table()
        { luaL_checktype(L, index, LUA_TTABLE); }

        template<typename T>
        inline void check_table(ArgCallback<T> cb, T& ud)
        {
            check_table();
            cb(L, index, ud);
        }

        template<typename T>
        inline bool opt_table(ArgCallback<T> cb, T& ud)
        {
            if ( exists() )
            {
                check_table(cb, ud);
                return true;
            }

            return false;
        }

        inline bool is_function()
        { return exists() && lua_isfunction(L, index); }

        // FIXIT-L we *may* need to insert checks for userdata, pointers, etc here

        inline bool is_int()
        { return is<int>(); }

        inline int get_int()
        { return get<int>(); }

        inline int check_int()
        { return check<int>("expected an integer"); }

        inline int check_int(int max)
        {
            int v = check_int();
            return argcheck((v <= max), v, "Too big");
        }

        inline int check_int(int min, int max)
        {
            int v = check_int(max);
            return argcheck((v >= min), v, "Too small");
        }

        inline int opt_int(int d = 0)
        { return ( exists() )? check_int() : d; }

        inline int opt_int(int d, int max)
        { return ( exists() )? check_int(max) : d; }

        inline int opt_int(int d, int min, int max)
        { return ( exists() )? check_int(min, max) : d; }

        inline bool is_size()
        { return is<unsigned>(); }

        inline unsigned get_size()
        { return get<unsigned>(); }

        inline unsigned check_size()
        { return check<unsigned>("expected an unsigned integer"); }

        inline unsigned check_size(unsigned max)
        {
            unsigned v = check_size();
            return argcheck((v <= max), v, "too big");
        }

        inline unsigned check_size(unsigned min, unsigned max)
        {
            unsigned v = check_size(max);
            return argcheck((v >= min), v, "too small");
        }

        inline unsigned opt_size(unsigned d = 0)
        { return ( exists() ) ? check_size() : d; }

        inline unsigned opt_size(unsigned d, unsigned max)
        { return ( exists() ) ? check_size(max) : d; }

        inline unsigned opt_size(unsigned d, unsigned min, unsigned max)
        { return ( exists() ) ? check_size(min, max) : d; }

        inline bool is_string()
        { return is<const char*>(); }

        inline const char* get_string()
        { return get<const char*>(); }

        inline const char* check_string()
        { return check<const char*>("expected a string"); }

        inline const char* check_string(size_t& len)
        { return check<const char*>("expected a string", len); }

        inline const char* opt_string(const char* d = "")
        { return ( exists() ) ? check_string() : d; }

        inline const char* opt_string(const char* d, size_t& len)
        { return ( exists() ) ? check_string(len) : d; }

        inline bool is_bool()
        { return is<bool>(); }

        inline bool get_bool()
        { return get<bool>(); }

        inline bool check_bool()
        { return check<bool>("expected a boolean"); }

        inline bool opt_bool(bool d = false)
        { return ( exists() ) ? check_bool() : d; }

    private:
        lua_State* L;
        const int count;

        template<typename T>
        inline T argcheck(bool cond, T v, const char* msg)
        {
            luaL_argcheck(L, exists() && cond, index, msg);
            return v;
        }

        template<typename T, typename... Args>
        inline T check(const char* msg, Args&&... args)
        {
            T v = 0;
            return argcheck(
                Stack<T>::validate(L, index, v, std::forward<Args>(args)...),
                v, msg
            );
        }

        inline bool is(int type)
        { return exists() && (type == lua_type(L, index)); }

        template<typename T>
        inline bool is()
        { return is(Stack<T>::type()); }

        template<typename T>
        inline T get()
        { return Stack<T>::get(L, index); }

    public:
        const int index;
    };

public:
    const int count;

    ArgRef operator[](int i)
    {
        if ( i < 0 )
            i += count + 1;

        // If the index is invalid, mark it as such with 0
        if ( i < 0 )
            i = 0;

        return ArgRef(L, count, i);
    }
};
}
#endif
