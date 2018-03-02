set (
    SMTP_TEST_LIBS
    utils
)

add_cpputest(detector_smtp_test ${SMTP_TEST_LIBS})

add_cpputest(http_url_patterns_test)

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


