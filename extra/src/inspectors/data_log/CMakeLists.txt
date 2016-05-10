cmake_minimum_required ( VERSION 2.8.11 )
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

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    data_log PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS data_log
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
