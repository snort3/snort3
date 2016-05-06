set ( TIME_INTERNAL_SOURCES
    packet_time.cc
    packet_time.h
    periodic.cc
    periodic.h
    timersub.h
    )

if ( ENABLE_UNIT_TESTS )
    list ( APPEND TIME_INTERNAL_SOURCES stopwatch_test.cc )
endif ( ENABLE_UNIT_TESTS )

set ( TIME_INCLUDES
    cpuclock.h
    clock_defs.h
    stopwatch.h
    )

add_library ( time STATIC
    ${TIME_INTERNAL_SOURCES}
    ${TIME_INCLUDES}
    )

install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)
