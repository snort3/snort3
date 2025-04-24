
add_cpputest( unix_transport_test
    SOURCES
        ../mp_unix_transport.cc
        ../../../side_channel/side_channel.cc
        ../../../side_channel/side_channel_format.cc
        ../../../framework/module.cc
        ../../../managers/connector_manager.cc
        $<TARGET_OBJECTS:catch_tests>
    LIBS
        ${CMAKE_THREAD_LIBS_INIT}
)

 add_cpputest( unix_transport_module_test
    SOURCES
        ../mp_unix_transport_module.cc
        ../../../framework/value.cc
        ../../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
        ../../../framework/module.cc
    LIBS
        ${CMAKE_THREAD_LIBS_INIT}
 )
 
