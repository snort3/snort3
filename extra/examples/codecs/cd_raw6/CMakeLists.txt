cmake_minimum_required ( VERSION 3.5.2 )
project ( cd_raw6 CXX )

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
    cd_raw6 SHARED
    cd_raw6.cc
)

set_target_properties (
    cd_raw6
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    cd_raw6 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_raw6
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
