add_cpputest( http_module_test
    SOURCES
        ../http_module.cc
        ../http_tables.cc
        ../http_normalizers.cc
        ../http_uri_norm.cc
        ../http_field.cc
        ../../../framework/module.cc
)

add_cpputest( http_msg_head_shared_util_test
    SOURCES
        ../http_msg_head_shared_util.cc
        ../http_field.cc
        ../http_str_to_code.cc
)

add_cpputest( http_normalizers_test
    SOURCES
        ../http_normalizers.cc
        ../http_field.cc
)

add_cpputest( http_transaction_test
    SOURCES
        ../http_transaction.cc
        ../http_flow_data.cc
        ../http_test_manager.cc
        ../http_test_input.cc
    LIBS ${ZLIB_LIBRARIES}
)

add_cpputest( http_uri_norm_test
    SOURCES
        ../http_uri_norm.cc
        ../http_module.cc
        ../http_test_manager.cc
        ../http_test_input.cc
        ../http_normalizers.cc
        ../http_str_to_code.cc
        ../http_field.cc
        ../http_tables.cc
        ../../../framework/module.cc
)
