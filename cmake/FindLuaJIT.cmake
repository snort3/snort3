#
#  FILE TAKEN FROM https://github.com/msva/lua-curl/blob/master/cmake/Modules/FindLuaJIT.cmake
#
# Locate LuaJIT library
# This module defines
#  LUAJIT_FOUND, if false, do not try to link to Lua
#  LUAJIT_LIBRARIES
#  LUAJIT_INCLUDE_DIRS, where to find lua.h
#  LUAJIT_VERSION_STRING, the version of Lua found (since CMake 2.8.8)

## Copied from default CMake FindLua51.cmake
set( LUA_PATHS
    ~/Library/Frameworks
    /Library/Frameworks
    /sw
    /opt/local
    /opt/csw
    /opt
)

set(ERROR_MESSAGE
    "\n\tCan't Find luajit!  Get it from
    http://luajit.org/download.html or use the --with-luajit-*
    options if you have it installed inn an unusual place.  You can
    also set the LUA_DIR environment variablet to the daqs root installation directory\n"
)


find_path(LUAJIT_INCLUDE_DIRS 
    NAMES luajit.h
    HINTS ENV LUA_DIR
    PATH_SUFFIXES include include/luajit-2.0
    PATHS ${LUA_PATHS}
)

find_library(LUAJIT_LIBRARIES
    NAMES luajit-5.1
    HINTS ENV LUA_DIR
    PATH_SUFFIXES luajit-5.1
    PATHS ${LUA_PATHS}
)

if (APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LUAJIT_LIBRARIES} -pagezero_size 10000 -image_base 100000000")
endif()

if(LUAJIT_LIBRARIES)
    # include the math library for Unix
    if(UNIX AND NOT APPLE)
        find_library(MATH_LIBRARY m)
        list(APPEND LUAJIT_LIBRARIES "${MATH_LIBRARY}")
    # For Windows and Mac, don't need to explicitly include the math library
    else()
        set( LUAJIT_LIBRARIES "${LUAJIT_LIBRARIES}" CACHE STRING "Lua Libraries")
    endif()
endif()


if(LUAJIT_INCLUDE_DIRS AND EXISTS "${LUAJIT_INCLUDE_DIRS}/luajit.h")
    file(STRINGS "${LUAJIT_INCLUDE_DIRS}/luajit.h" luajit_version_str REGEX "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT .+\"")

    string(REGEX REPLACE "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT ([^\"]+)\".*" "\\1" LUAJIT_VERSION_STRING "${luajit_version_str}")
    unset(luajit_version_str)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to TRUE if
# all listed variables are TRUE
find_package_handle_standard_args(LuaJIT
    REQUIRED_VARS LUAJIT_LIBRARIES LUAJIT_INCLUDE_DIRS
    VERSION_VAR LUAJIT_VERSION_STRING
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    LUAJIT_INCLUDE_DIRS 
    LUAJIT_LIBRARIES 
    MATH_LIBRARY
)

