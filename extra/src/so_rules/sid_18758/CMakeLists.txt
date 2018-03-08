cmake_minimum_required ( VERSION 3.4.3 )
project ( sid_18758 CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

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

target_include_directories (
    sid_18758 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS sid_18758
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/so_rules"
)
