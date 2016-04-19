cmake_minimum_required ( VERSION 3.5.2 )
project ( ips_pkt_num CXX )

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
    ips_pkt_num SHARED
    ips_pkt_num.cc
)

set_target_properties (
    ips_pkt_num
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    ips_pkt_num PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ips_pkt_num
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/ips_options"
)
