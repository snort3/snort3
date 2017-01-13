cmake_minimum_required ( VERSION 2.8.11 )
project ( lowmem CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    lowmem MODULE
    lowmem.cc
    sfksearch.cc
    sfksearch.h
    trie_api.cc
)

if ( APPLE )
    set_target_properties (
        lowmem
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    lowmem
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    lowmem PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS lowmem
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/search_engines"
)
