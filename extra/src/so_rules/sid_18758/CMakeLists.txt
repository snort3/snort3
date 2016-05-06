cmake_minimum_required ( VERSION 2.8.11 )
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
    sid_18758.h
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )
if ( DAQ_CPPFLAGS )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DAQ_CPPFLAGS}" )
endif ( DAQ_CPPFLAGS )

target_include_directories (
    sid_18758 PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS sid_18758
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/so_rules"
)
