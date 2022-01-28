add_cpputest( pub_sub_http_event_test
    SOURCES
        ../http_events.cc
)
add_cpputest( pub_sub_http_request_body_event_test
    SOURCES
        ../http_request_body_event.cc
        ../../service_inspectors/http_inspect/http_msg_body_cl.cc
)
add_cpputest( pub_sub_eve_process_event_test
    SOURCES
        ../eve_process_event.h
)
