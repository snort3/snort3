cmake_minimum_required ( VERSION 2.8.11 )
project ( cd_pim CXX )

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
    cd_pim SHARED
    cd_pim.cc
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

target_include_directories (
    cd_pim PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_pim
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
