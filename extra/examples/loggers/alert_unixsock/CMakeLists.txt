cmake_minimum_required ( VERSION 3.5.2 )
project ( alert_unixsock CXX )

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
    alert_unixsock SHARED
    alert_unixsock.cc
)

set_target_properties (
    alert_unixsock
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    alert_unixsock PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS alert_unixsock
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
