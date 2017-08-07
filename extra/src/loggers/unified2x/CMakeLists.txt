cmake_minimum_required ( VERSION 2.8.11 )
project ( unified2x CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    unified2x MODULE
    unified2x.cc
    unified2x.h
)

if ( APPLE )
    set_target_properties (
        unified2x
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    unified2x
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    unified2x PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS unified2x
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
