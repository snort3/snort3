
set (LOGGER_SOURCES
    alert_luajit.cc
    alert_sf_socket.cc
    log_codecs.cc
    loggers.cc
    loggers.h
)

set (PLUGIN_LIST
    alert_csv.cc
    alert_fast.cc
    alert_full.cc
    alert_json.cc
    alert_syslog.cc
    alert_unixsock.cc
    log_hext.cc
    log_pcap.cc
    unified2.cc
)

if (STATIC_LOGGERS)
    add_library ( loggers OBJECT
        ${LOGGER_SOURCES}
        ${PLUGIN_LIST}
    )


else (STATIC_LOGGERS)

    add_library ( loggers OBJECT
        ${LOGGER_SOURCES}
    )

    add_dynamic_module(alert_csv loggers alert_csv.cc)
    add_dynamic_module(alert_fast loggers alert_fast.cc)
    add_dynamic_module(alert_full loggers alert_full.cc)
    add_dynamic_module(alert_json loggers alert_json.cc)
    add_dynamic_module(alert_syslog loggers alert_syslog.cc)
    add_dynamic_module(alert_unixsock loggers alert_unixsock.cc)
    add_dynamic_module(log_hext loggers log_hext.cc)
    add_dynamic_module(log_pcap loggers log_pcap.cc)
    add_dynamic_module(unified2 loggers unified2.cc)

endif (STATIC_LOGGERS)

