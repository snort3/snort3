add_library (lua STATIC
    lua.cc
    lua.h
    lua_iface.cc
    lua_iface.h
    lua_util.cc
    lua_util.h
    lua_table.h
    lua_stack.h
    lua_arg.h
)

target_include_directories(lua PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
