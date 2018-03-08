cmake_minimum_required ( VERSION 3.4.3 )
project ( daq_regtest C )

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS ON)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    daq_regtest MODULE
    daq_regtest.c
)

if ( APPLE )
    set_target_properties (
        daq_regtest
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    daq_regtest
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    daq_regtest PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS daq_regtest
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/daqs"
)
