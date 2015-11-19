
if ( HAVE_HYPERSCAN )
    add_cpputest(ips_regex_test ips_options
        ips_options
        framework
        sfip
        catch_tests
)
endif()

target_link_libraries(ips_regex_test ${HS_LIBRARIES})
target_include_directories(ips_regex_test PUBLIC ${LUAJIT_INCLUDE_DIR})

