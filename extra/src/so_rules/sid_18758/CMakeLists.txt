cmake_minimum_required ( VERSION 2.8.11 )
project ( sid_18758 CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    sid_18758 MODULE
    sid_18758.cc
    sid_18758.h
)

if ( APPLE )
    set_target_properties (
        sid_18758
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    sid_18758
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    sid_18758 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS sid_18758
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/so_rules"
)
