cmake_minimum_required ( VERSION 2.8.11 )
project ( data_log CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    data_log MODULE
    data_log.cc
)

if ( APPLE )
    set_target_properties (
        data_log
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    data_log
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    data_log PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS data_log
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
