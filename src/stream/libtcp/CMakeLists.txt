
add_library( stream_libtcp STATIC
	tcp_segment_descriptor.cc
    tcp_stream_tracker.cc
	tcp_state_handler.cc
	tcp_state_machine.cc
	stream_tcp_unit_test.cc
)
