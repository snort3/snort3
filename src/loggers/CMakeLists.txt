## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as
## published by the Free Software Foundation.  You may not use, modify or
## distribute this program under any other version of the GNU General
## Public License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


include_directories(${LUAJIT_INCLUDE_DIR})

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
    alert_test.cc
    alert_unixsock.cc
    log_null.cc
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
    add_shared_library(alert_test loggers alert_test.cc)
    add_shared_library(alert_unixsock loggers alert_unixsock.cc)
    add_shared_library(log_null loggers log_null.cc)
    add_shared_library(log_pcap loggers log_pcap.cc)
    add_shared_library(unified2 loggers unified2.cc unified2_common.h)

endif (STATIC_LOGGERS)

