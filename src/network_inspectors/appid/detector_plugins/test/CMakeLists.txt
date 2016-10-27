set (
    SMTP_TEST_LIBS
    utils
)

add_library(smtp_test_depends_on_lib ../../appid_stats_counter.cc)

add_cpputest(detector_smtp_test smtp_test_depends_on_lib ${SMTP_TEST_LIBS})

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


