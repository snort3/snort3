cmake_minimum_required ( VERSION 2.8.11 )
project ( dpx CXX )

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
    dpx SHARED
    dpx.cc
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

target_include_directories (
    dpx PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS dpx
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
