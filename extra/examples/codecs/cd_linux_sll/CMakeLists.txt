cmake_minimum_required ( VERSION 3.5.2 )
project ( cd_linux_sll CXX )

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
    cd_linux_sll SHARED
    cd_linux_sll.cc
)

set_target_properties (
    cd_linux_sll
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    cd_linux_sll PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_linux_sll
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
