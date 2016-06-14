#
# Locate LuaJIT library
# This module defines
#  LUAJIT_FOUND, if false, do not try to link to Lua
#  LUAJIT_LIBRARIES
#  LUAJIT_INCLUDE_DIR, where to find lua.h
#  LUAJIT_VERSION_STRING, the version of LuaJIT found

set(ERROR_MESSAGE
    "\n\tCan't Find luajit!  Get it from
    http://luajit.org/download.html or use the --with-luajit-*
    options if you have it installed inn an unusual place.\n"
)

find_package(PkgConfig)
pkg_check_modules(PC_LUAJIT luajit)

# Use LUAJIT_INCLUDE_DIR_HINT and LUAJIT_LIBRARY_DIR_HINT from configure_cmake.sh as primary hints
# and then package config information after that.
find_path(LUAJIT_INCLUDE_DIR luajit.h
    HINTS ${LUAJIT_INCLUDE_DIR_HINT} ${PC_LUAJIT_INCLUDEDIR} ${PC_LUAJIT_INCLUDE_DIRS})
find_library(LUAJIT_LIBRARIES NAMES luajit-5.1
    HINTS ${LUAJIT_LIBRARIES_DIR_HINT} ${PC_LUAJIT_LIBDIR} ${PC_LUAJIT_LIBRARY_DIRS})

if (APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LUAJIT_LIBRARIES} -pagezero_size 10000 -image_base 100000000")
endif()

if(LUAJIT_INCLUDE_DIR AND EXISTS "${LUAJIT_INCLUDE_DIR}/luajit.h")
    file(STRINGS "${LUAJIT_INCLUDE_DIR}/luajit.h" luajit_version_str REGEX "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT .+\"")

    string(REGEX REPLACE "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT ([^\"]+)\".*" "\\1" LUAJIT_VERSION_STRING "${luajit_version_str}")
    unset(luajit_version_str)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to TRUE if
# all listed variables are TRUE
find_package_handle_standard_args(LuaJIT
    REQUIRED_VARS LUAJIT_LIBRARIES LUAJIT_INCLUDE_DIR
    VERSION_VAR LUAJIT_VERSION_STRING
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(LUAJIT_INCLUDE_DIR LUAJIT_LIBRARIES)

