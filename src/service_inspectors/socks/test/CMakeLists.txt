add_cpputest( socks_module_test
    SOURCES
        ../socks_module.cc
        ../../../framework/module.cc
)

add_cpputest( socks_flow_data_test
    SOURCES
        ../socks_flow_data.cc
        ../../../sfip/sf_ip.cc
)

add_cpputest( socks_handoff_test
    SOURCES
        ../socks_flow_data.cc
)

add_cpputest( socks_splitter_test
    SOURCES
        ../socks_splitter.cc
        ../socks_flow_data.cc
)

add_cpputest( socks_negative_test
    SOURCES
        ../socks.cc
        ../socks_module.cc
        ../socks_splitter.cc
        ../socks_flow_data.cc
        ../../../sfip/sf_ip.cc
        ../../../framework/module.cc
)

add_cpputest( socks_ips_test
    SOURCES
        socks_ips_test.cc
        ../socks_flow_data.cc
)

add_cpputest( socks_splitter_negative_test
    SOURCES
        ../socks_splitter.cc
        ../socks_flow_data.cc
        ../../../sfip/sf_ip.cc
)
