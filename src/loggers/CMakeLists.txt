
set (LOGGER_SOURCES
    alert_luajit.cc
    log_codecs.cc
    loggers.cc
    loggers.h
)

set (PLUGIN_LIST
    alert_csv.cc
    alert_fast.cc
    alert_full.cc
    alert_syslog.cc
    log_hext.cc
    log_pcap.cc
    unified2.cc
    unified2_common.h
)

if (LINUX)
    set ( LOGGER_SOURCES
        ${LOGGER_SOURCES}
        alert_sf_socket.cc
    )
endif()


if (STATIC_LOGGERS)
    add_library ( loggers STATIC
        ${LOGGER_SOURCES}
        ${PLUGIN_LIST}
    )


else (STATIC_LOGGERS)

    add_library ( loggers STATIC
        ${LOGGER_SOURCES}
    )

    add_shared_library(alert_csv loggers alert_csv.cc)
    add_shared_library(alert_fast loggers alert_fast.cc)
    add_shared_library(alert_full loggers alert_full.cc)
    add_shared_library(alert_syslog loggers alert_syslog.cc)
    add_shared_library(log_hext loggers log_hext.cc)
    add_shared_library(log_pcap loggers log_pcap.cc)
    add_shared_library(unified2 loggers unified2.cc unified2_common.h)

endif (STATIC_LOGGERS)

