cmake_minimum_required ( VERSION 2.8.11 )
project ( daq_socket C )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
    set (
        CMAKE_SHARED_LINKER_FLAGS
        "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup"
    )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    daq_socket SHARED
    daq_socket.c
)

target_include_directories (
    daq_socket PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS daq_socket
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/daqs"
)
