
set (FILTER_INCLUDES
    sfrf.h 
)

if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES
        sfrf_test.cc
        sfthd_test.cc
    )
endif()

add_library (filter STATIC
    detection_filter.cc
    detection_filter.h
    rate_filter.cc
    rate_filter.h
    sfthreshold.cc
    sfthreshold.h
    sfrf.cc
    sfthd.cc
    sfthd.h
    ${FILTER_INCLUDES}
    ${TEST_FILES}
)

install(FILES ${FILTER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/filters"
)

