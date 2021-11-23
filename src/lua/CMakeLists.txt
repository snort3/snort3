
if ( ENABLE_PIGLET )
    set(PIGLET_FILES
        lua_arg.h
        lua_iface.h
        lua_ref.cc
        lua_ref.h
        lua_table.h
        lua_util.cc
        lua_util.h
    )
endif ()

add_library (lua OBJECT
    lua.cc
    lua.h
    lua_script.h
    lua_stack.h
    ${PIGLET_FILES}
)

target_include_directories(lua PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(test)
