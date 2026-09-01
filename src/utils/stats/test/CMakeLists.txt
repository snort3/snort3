add_catch_test( stats_output_json_test
    SOURCES
        stats_output_json_test.cc
        ../output_json.cc
        ../utils.cc
        ../../../helpers/json_stream.cc
)

add_catch_test( stats_output_text_test
    SOURCES
        stats_output_text_test.cc
        ../utils.cc
)

add_catch_test( response_buf_test
    SOURCES
        response_buf_test.cc
        ../response_buf.cc
)
