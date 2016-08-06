
set (FILE_LIST
    http_inspect.cc
    hi_main.cc
    hi_main.h
    hi_ad.cc
    hi_ad.h
    hi_client.cc
    hi_client.h
    hi_client_norm.cc
    hi_client_norm.h
    hi_cmd_lookup.cc
    hi_cmd_lookup.h
    hi_events.cc
    hi_events.h
    hi_include.h
    hi_mi.cc
    hi_mi.h
    hi_norm.cc
    hi_norm.h
    hi_module.cc
    hi_module.h
    hi_reqmethod_check.h
    hi_return_codes.h
    hi_server.cc
    hi_server.h
    hi_server_norm.cc
    hi_server_norm.h
    hi_si.cc
    hi_si.h
    hi_stream_splitter.cc
    hi_stream_splitter.h
    hi_ui_config.cc
    hi_ui_config.h
    hi_ui_iis_unicode_map.cc
    hi_ui_iis_unicode_map.h
    hi_util.h
    ips_http.cc
    ips_http_header.cc
)

cmake_minimum_required ( VERSION 2.8.11 )
project ( http_server CXX )

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
    http_server SHARED
    ${FILE_LIST}
)

set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )

target_include_directories (
    http_server PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS http_server
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)

