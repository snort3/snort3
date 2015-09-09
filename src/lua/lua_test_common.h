#ifndef LUA_TEST_COMMON_H
#define LUA_TEST_COMMON_H

#include <utility>
#include <string.h>
#include <luajit-2.0/lua.hpp>

static inline void l_end_lua_state(lua_State*& L_ptr)
{
    if ( L_ptr )
    {
        lua_close(L_ptr);
        L_ptr = nullptr;
    }
}

static inline void l_reset_lua_state(lua_State*& L_ptr)
{
    l_end_lua_state(L_ptr);
    L_ptr = luaL_newstate();
    luaL_openlibs(L_ptr);
}

template<typename T, size_t N>
static inline constexpr size_t sizeofArray(T (&)[N])
{ return N; }

#endif
