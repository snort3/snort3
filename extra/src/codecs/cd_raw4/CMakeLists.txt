cmake_minimum_required ( VERSION 3.4.3 )
project ( cd_raw4 CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    cd_raw4 MODULE
    cd_raw4.cc
)

if ( APPLE )
    set_target_properties (
        cd_raw4
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    cd_raw4
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    cd_raw4 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_raw4
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/codecs"
)
