
if ( HAVE_HYPERSCAN )
add_cpputest(ips_regex_test ips_options
    ips_options
    framework
    sfip
    catch_tests
    hs
)
endif()

