cmake_minimum_required ( VERSION 2.8.11 )
project ( daq_regtest C )

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

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99" )

target_include_directories (
    daq_regtest PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS daq_regtest
    LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/daqs"
)
