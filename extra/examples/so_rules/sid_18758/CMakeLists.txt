cmake_minimum_required ( VERSION 3.5.2 )
project ( sid_18758 CXX )

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
    sid_18758 SHARED
    sid_18758.cc
)

set_target_properties (
    sid_18758
    PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
)

target_include_directories (
    sid_18758 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS sid_18758
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/so_rules"
)
