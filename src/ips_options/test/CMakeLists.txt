
if ( HAVE_HYPERSCAN )
    add_cpputest( ips_regex_test
        SOURCES
            ../ips_regex.cc
            ../../framework/module.cc
            ../../framework/ips_option.cc
            ../../framework/value.cc
            ../../sfip/sf_ip.cc
            $<TARGET_OBJECTS:catch_tests>
        LIBS
            ${HS_LIBRARIES}
    )
endif()
