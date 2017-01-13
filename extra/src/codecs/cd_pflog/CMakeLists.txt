cmake_minimum_required ( VERSION 2.8.11 )
project ( cd_pflog CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    cd_pflog MODULE
    cd_pflog.cc
)

if ( APPLE )
    set_target_properties (
        cd_pflog
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    cd_pflog
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    cd_pflog PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_pflog
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
