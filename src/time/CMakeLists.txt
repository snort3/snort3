set ( TIME_INCLUDES
    clock_defs.h
    packet_time.h
    stopwatch.h
)

set ( TIME_INTERNAL_SOURCES
    packet_time.cc
    periodic.cc
    periodic.h
    timersub.h
)

if ( USE_TSC_CLOCK )
    list ( APPEND TIME_INCLUDES tsc_clock.h )
    list ( APPEND TIME_INTERNAL_SOURCES tsc_clock.cc )
endif ( USE_TSC_CLOCK )

if ( ENABLE_UNIT_TESTS )
    list ( APPEND TIME_INTERNAL_SOURCES stopwatch_test.cc )
endif ( ENABLE_UNIT_TESTS )

add_library ( time OBJECT
    ${TIME_INTERNAL_SOURCES}
    ${TIME_INCLUDES}
)

install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)
