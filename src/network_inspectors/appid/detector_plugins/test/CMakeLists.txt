set (
    SMTP_TEST_LIBS
    utils
)

add_cpputest(detector_smtp_test ${SMTP_TEST_LIBS})

include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )


