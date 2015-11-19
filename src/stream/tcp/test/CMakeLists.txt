
include_directories( ../../../network_inspectors ${LUAJIT_INCLUDE_DIR} )

add_library( stream_tcp_test
	../tcp_normalizer.cc
	../tcp_normalizers.cc
	../../../protocols/tcp_options.cc
	../../../main/snort_debug.cc
)

# this test is broken, uncomment below when fixed
#add_cpputest( tcp_normalizer_test stream_tcp_test )

