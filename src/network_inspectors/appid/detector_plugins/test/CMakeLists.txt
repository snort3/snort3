
include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_cpputest( detector_smtp_test 
    SOURCES
        ../../../../utils/util_cstring.cc )

add_cpputest( http_url_patterns_test
    SOURCES
        ../../../../utils/util_cstring.cc )

add_cpputest( detector_sip_test 
    SOURCES
        ../../../../utils/util_cstring.cc
        ../../appid_utils/sf_mlmp.cc )

add_cpputest( detector_pop3_test
    SOURCES
        ../../../../utils/util_cstring.cc )
