add_cpputest( file_connector_test
    SOURCES
        ../file_connector.cc
        ../../../framework/module.cc
)

add_cpputest( file_connector_module_test
    SOURCES
        ../file_connector_module.cc
        ../../../framework/module.cc
        ../../../framework/value.cc
        ../../../sfip/sf_ip.cc
        $<TARGET_OBJECTS:catch_tests>
)

