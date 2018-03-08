
if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES
        sfrf_test.cc
        sfthd_test.cc
    )
endif()

add_library (filter OBJECT
    detection_filter.cc
    detection_filter.h
    rate_filter.cc
    rate_filter.h
    sfthreshold.cc
    sfthreshold.h
    sfrf.cc
    sfrf.h
    sfthd.cc
    sfthd.h
    ${TEST_FILES}
)

