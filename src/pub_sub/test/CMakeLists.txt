if ( ENABLE_UNIT_TESTS )
    add_library(extr_cpputest_deps OBJECT EXCLUDE_FROM_ALL
        ../../sfip/sf_ip.cc
    )
endif ( ENABLE_UNIT_TESTS )

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
add_cpputest( pub_sub_http_transaction_end_event_test
    SOURCES
        ../http_transaction_end_event.cc
        ../../service_inspectors/http_inspect/http_transaction.cc
        ../../service_inspectors/http_inspect/http_flow_data.cc
        ../../service_inspectors/http_inspect/http_test_manager.cc
        ../../service_inspectors/http_inspect/http_test_input.cc
    LIBS ${ZLIB_LIBRARIES}
)
add_cpputest( pub_sub_ftp_events_test
    SOURCES
        ../ftp_events.h
        $<TARGET_OBJECTS:extr_cpputest_deps>
)
