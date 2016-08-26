add_cpputest(http_uri_norm_test http_inspect framework)
add_cpputest(http_normalizers_test http_inspect framework)
add_cpputest(http_module_test http_inspect framework)
add_cpputest(http_msg_head_shared_util_test http_inspect framework)

# FIXIT-M this doesn't link properly under cmake. Autotools version is working.
# add_library(depends_on_lib_transaction ../http_transaction.cc ../http_flow_data.cc ../http_test_manager.cc ../http_test_input.cc)
# add_cpputest(http_transaction_test depends_on_lib_transaction framework -lz)

