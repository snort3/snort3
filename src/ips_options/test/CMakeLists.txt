
if ( HAVE_HYPERSCAN )
    add_cpputest( ips_regex_test
        SOURCES
            ../ips_regex.cc
            ../../framework/ips_option.cc
            ../../framework/module.cc
            ../../framework/value.cc
            ../../helpers/hyper_scratch_allocator.cc
            ../../helpers/scratch_allocator.cc
            ../../sfip/sf_ip.cc
            $<TARGET_OBJECTS:catch_tests>
        LIBS
            ${HS_LIBRARIES}
    )
endif()
