cmake_minimum_required ( VERSION 2.8.11 )
project ( dpx CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    dpx MODULE
    dpx.cc
)

if ( APPLE )
    set_target_properties (
        dpx
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    dpx
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    dpx PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS dpx
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
