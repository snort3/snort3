
add_library (lua OBJECT
    lua.cc
    lua.h
    lua_script.h
    lua_stack.h
)

target_include_directories(lua PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(test)
