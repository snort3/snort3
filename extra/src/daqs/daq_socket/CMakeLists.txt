cmake_minimum_required ( VERSION 2.8.11 )
project ( daq_socket C )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
    set (
        CMAKE_MODULE_LINKER_FLAGS
        "${CMAKE_MODULE_LINKER_FLAGS} -undefined dynamic_lookup"
    )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    daq_socket MODULE
    daq_socket.c
)

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99" )
if ( DAQ_CPPFLAGS )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DAQ_CPPFLAGS}" )
endif ( DAQ_CPPFLAGS )

target_include_directories (
    daq_socket PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS daq_socket
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/daqs"
)
