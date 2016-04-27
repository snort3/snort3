cmake_minimum_required ( VERSION 2.8.11 )
project ( cd_eapol CXX )

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
    cd_eapol SHARED
    cd_eapol.cc
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

target_include_directories (
    cd_eapol PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_eapol
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
