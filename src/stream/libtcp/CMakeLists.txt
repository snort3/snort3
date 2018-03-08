
if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES stream_tcp_unit_test.cc)
endif()


add_library( stream_libtcp OBJECT
	tcp_segment_descriptor.cc
	tcp_state_handler.cc
	tcp_state_machine.cc
    tcp_stream_session.cc
    tcp_stream_tracker.cc
    tcp_segment_descriptor.h
    tcp_state_handler.h
    tcp_state_machine.h
    tcp_stream_session.h
    tcp_stream_tracker.h
    ${TEST_FILES}
)
