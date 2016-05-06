cmake_minimum_required ( VERSION 2.8.11 )
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

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )
if ( DAQ_CPPFLAGS )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DAQ_CPPFLAGS}" )
endif ( DAQ_CPPFLAGS )

target_include_directories (
    cd_linux_sll PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_linux_sll
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/codecs"
)
