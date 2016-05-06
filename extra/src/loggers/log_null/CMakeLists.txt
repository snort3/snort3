cmake_minimum_required ( VERSION 2.8.11 )
project ( log_null CXX )

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
    log_null SHARED
    log_null.cc
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )
if ( DAQ_CPPFLAGS )
    set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DAQ_CPPFLAGS}" )
endif ( DAQ_CPPFLAGS )

target_include_directories (
    log_null PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS log_null
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/loggers"
)
