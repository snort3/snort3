set ( TIME_INTERNAL_SOURCES
    packet_time.cc
    packet_time.h
    periodic.cc
    periodic.h
    timersub.h
    )

set ( TIME_INCLUDES
    cpuclock.h
    )

add_library ( time STATIC
    ${TIME_INTERNAL_SOURCES}
    ${TIME_INCLUDES}
    )

install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)
