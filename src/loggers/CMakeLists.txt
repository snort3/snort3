
include_directories(${LUAJIT_INCLUDE_DIR})

set ( LOGGER_SOURCES
    loggers.cc
    loggers.h
)

set ( PLUGIN_LIST
    alert_csv.cc
    alert_fast.cc
    alert_full.cc
    alert_syslog.cc
    alert_test.cc
    alert_unixsock.cc
    log_null.cc
    log_tcpdump.cc
    unified2.cc
    unified2_common.h
)

if( LINUX )
    set ( PLUGIN_LIST
        ${PLUGIN_LIST}
        alert_sf_socket.cc
    )
endif()


if (STATIC_LOGGERS)
    add_library ( loggers STATIC
        ${LOGGER_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_LOGGERS)

    add_library ( logger SHARED
        ${LOGGER_SOURCES}
    )

    add_shared_library(alert_csv loggers alert_csv.cc)
    add_shared_library(alert_fast loggers alert_fast.cc)
    add_shared_library(alert_full loggers alert_full.cc)
    add_shared_library(alert_syslog loggers alert_syslog.cc)
    add_shared_library(alert_test loggers alert_test.cc)
    add_shared_library(alert_unixsock loggers alert_unixsock.cc)
    add_shared_library(log_null loggers log_null.cc)
    add_shared_library(log_tcpdump loggers log_tcpdump.cc)
    add_shared_library(unified2 loggers unified2.cc unified2_common.h)

endif (STATIC_LOGGERS)

