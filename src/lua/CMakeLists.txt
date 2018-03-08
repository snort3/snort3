
if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES lua_stack_test.cc)
endif()

add_library (lua OBJECT
    lua.cc
    lua.h
    lua_ref.cc
    lua_ref.h
    lua_iface.h
    lua_util.cc
    lua_util.h
    lua_table.h
    lua_stack.h
    lua_arg.h
    ${TEST_FILES}
)

target_include_directories(lua PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

