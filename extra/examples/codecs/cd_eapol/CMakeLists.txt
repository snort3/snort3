cmake_minimum_required ( VERSION 3.5.2 )
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

set_target_properties (
    cd_eapol
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    cd_eapol PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_eapol
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
