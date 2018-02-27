cmake_minimum_required ( VERSION 2.8.11 )
project ( ips_wscale CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    ips_wscale MODULE
    ips_wscale.cc
)

if ( APPLE )
    set_target_properties (
        ips_wscale
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    ips_wscale
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    ips_wscale PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ips_wscale
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/ips_options"
)
