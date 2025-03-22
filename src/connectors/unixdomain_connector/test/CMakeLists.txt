
add_cpputest( unixdomain_connector_test
    SOURCES
        ../unixdomain_connector.cc
        ../../../framework/module.cc
        ../../../managers/connector_manager.cc
    LIBS
        ${CMAKE_THREAD_LIBS_INIT}
)

add_cpputest( unixdomain_connector_module_test
    SOURCES
        ../unixdomain_connector_module.cc
        ../../../framework/module.cc
        ../../../framework/parameter.cc
        ../../../framework/value.cc
        ../../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${DNET_LIBRARIES}
)

