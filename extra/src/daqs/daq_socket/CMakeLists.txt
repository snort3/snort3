cmake_minimum_required ( VERSION 3.4.3 )
project ( daq_socket C )

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS ON)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    daq_socket MODULE
    daq_socket.c
)

if ( APPLE )
    set_target_properties (
        daq_socket
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    daq_socket
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    daq_socket PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS daq_socket
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/daqs"
)
