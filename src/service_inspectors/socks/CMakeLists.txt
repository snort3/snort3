set(SOCKS_INCLUDES
    socks_module.h
    socks.h
    socks_flow_data.h
    socks_splitter.h
    socks_event.h
    socks_ips.h
)

set(SOCKS_SOURCES
    ${SOCKS_INCLUDES}
    socks_module.cc
    socks.cc
    socks_flow_data.cc
    socks_splitter.cc
    socks_ips.cc
)

#if(STATIC_INSPECTORS)
    add_library(socks OBJECT ${SOCKS_SOURCES})

#else()
    # SOCKS cannot be built as a dynamic module because it uses
    # Analyzer::get_local_analyzer() which is only available in the main binary
    #add_dynamic_module(socks inspectors ${SOCKS_SOURCES})

#endif()

target_include_directories(socks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Add test directory if testing is enabled
if(ENABLE_UNIT_TESTS)
    add_subdirectory(test)
endif()
