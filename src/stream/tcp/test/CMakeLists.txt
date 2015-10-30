include_directories( ../../../network_inspectors )
add_library( stream_tcp_test 
	../tcp_normalizer.cc
	../tcp_normalizers.cc
	../../../protocols/tcp_options.cc
	../../../main/snort_debug.cc
)

add_cpputest( tcp_normalizer_test stream_tcp_test )
