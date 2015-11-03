
# neither of these work ... :(
#pkg_check_modules(HS QUIET libhs)
#pkg_search_module(HS QUIET libhs)
# (and they shouldn't muck with PKG_CONFIG_PATH)
# so here we are ...

execute_process(
    COMMAND pkg-config --cflags-only-I libhs
    RESULT_VARIABLE result
    OUTPUT_VARIABLE include_hints
    ERROR_QUIET
)

if (result)
    set(include_hints " ")
else ()
    # remove -I
    string(STRIP ${include_hints} include_hints)
    string(SUBSTRING ${include_hints} 2 -1 include_hints)

    # remote trailing /hs
    string(REGEX REPLACE "/hs$" "" include_hints ${include_hints})
endif()

execute_process(
    COMMAND pkg-config --libs-only-L libhs
    RESULT_VARIABLE result
    OUTPUT_VARIABLE lib_hints
    ERROR_QUIET
)

if (result)
    set(lib_hints " ")
else ()
    # remove -L
    string(STRIP ${lib_hints} lib_hints)
    string(SUBSTRING ${lib_hints} 2 -1 lib_hints)
endif()

find_path (HS_INCLUDE_DIRS NAMES hs/hs_compile.h HINTS ${include_hints})

find_library(HS_LIBRARIES NAMES hs HINTS ${lib_hints})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HS REQUIRED_VARS HS_INCLUDE_DIRS HS_LIBRARIES)

mark_as_advanced(HS_INCLUDE_DIRS HS_LIBRARIES)

