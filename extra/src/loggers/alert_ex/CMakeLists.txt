cmake_minimum_required ( VERSION 2.8.11 )
project ( alert_ex CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    alert_ex MODULE
    alert_ex.cc
)

if ( APPLE )
    set_target_properties (
        alert_ex
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    alert_ex
    PROPERTIES
        PREFIX ""
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    alert_ex PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS alert_ex
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
