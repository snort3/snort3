cmake_minimum_required ( VERSION 2.8.11 )
project ( ips_urg CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    ips_urg MODULE
    ips_urg.cc
)

if ( APPLE )
    set_target_properties (
        ips_urg
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    ips_urg
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    ips_urg PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ips_urg
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/ips_options"
)
