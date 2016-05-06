cmake_minimum_required ( VERSION 2.8.11 )
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

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )
if ( DAQ_CPPFLAGS )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DAQ_CPPFLAGS}" )
endif ( DAQ_CPPFLAGS )

target_include_directories (
    ips_pkt_num PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ips_pkt_num
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/ips_options"
)
