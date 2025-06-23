if (ENABLE_BENCHMARK_TESTS)

    add_catch_test( extractor_benchmark
        SOURCES
            ../extractor_csv_logger.cc
            ../extractor_json_logger.cc
            ${CMAKE_SOURCE_DIR}/src/helpers/json_stream.cc
            ${CMAKE_SOURCE_DIR}/src/sfip/sf_ip.cc
            ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
            ${CMAKE_SOURCE_DIR}/src/utils/util.cc
    )

endif(ENABLE_BENCHMARK_TESTS)
