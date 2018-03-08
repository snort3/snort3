
add_cpputest( tcp_connector_test
    SOURCES
        ../tcp_connector.cc
        ../../../framework/module.cc
    LIBS
        ${CMAKE_THREAD_LIBS_INIT}
)

add_cpputest( tcp_connector_module_test
    SOURCES
        ../tcp_connector_module.cc
        ../../../framework/module.cc
        ../../../framework/parameter.cc
        ../../../framework/value.cc
        ../../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
)

