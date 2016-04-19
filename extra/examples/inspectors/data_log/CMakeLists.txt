cmake_minimum_required ( VERSION 3.5.2 )
project ( data_log CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
    set (
        CMAKE_SHARED_LINKER_FLAGS
        "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup"
    )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    data_log SHARED
    data_log.cc
)

set_target_properties (
    data_log
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    data_log PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS data_log
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
