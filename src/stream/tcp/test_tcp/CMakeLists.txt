enable_testing()
add_executable( tcp_normalizer_test 
	tcp_normalizer_test.cc
	../tcp_normalizer.cc
	../tcp_normalizers.cc
	../../../protocols/tcp_options.cc
	../../../main/snort_debug.cc
)
target_link_libraries(tcp_normalizer_test ${LIBS})
target_link_libraries(tcp_normalizer_test CppUTest )
target_link_libraries(tcp_normalizer_test CppUTestExt )
add_test(tcp_normalizer_test ${CMAKE_CURRENT_BINARY_DIR}/tcp_normalizer_test)
