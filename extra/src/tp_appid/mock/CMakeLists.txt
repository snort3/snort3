cmake_minimum_required ( VERSION 3.4.3 )
project ( lowmem CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
  tp_mock MODULE
  tp_mock.cc
)

if ( APPLE )
    set_target_properties (
      tp_lib
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
  tp_mock
    PROPERTIES
        PREFIX ""
	)

set_property(TARGET tp_mock PROPERTY ENABLE_EXPORTS 1)      

target_include_directories (
    tp_mock PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS tp_mock
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/tp_appid"
)
