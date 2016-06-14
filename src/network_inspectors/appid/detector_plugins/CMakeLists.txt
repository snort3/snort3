set ( DETECTOR_PLUGINS_SOURCES
    detector_api.h
    detector_base.cc
    detector_base.h
    detector_dns.cc
    detector_dns.h
    detector_http.cc
    detector_http.h
    detector_imap.cc
    detector_kerberos.cc
    detector_pattern.cc
    detector_pattern.h
    detector_pop3.cc
    detector_sip.cc
    detector_sip.h
    http_url_patterns.cc
    http_url_patterns.h
    )

add_library ( appid_detector_plugins STATIC
    ${DETECTOR_PLUGINS_SOURCES}
)

target_include_directories ( appid_detector_plugins PRIVATE ${APPID_INCLUDE_DIR} )

#  FIXIT-H: Add unit tests

#install (FILES ${DETECTOR_PLUGINS_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid/detector_plugins"
#)
