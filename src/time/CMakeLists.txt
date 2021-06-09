set ( TIME_INCLUDES
    clock_defs.h
    packet_time.h
    periodic.h
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

add_library ( time OBJECT
    ${TIME_INTERNAL_SOURCES}
    ${TIME_INCLUDES}
)

install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)

add_catch_test( periodic_test
    NO_TEST_SOURCE
    SOURCES
        periodic.cc
)

add_subdirectory(test)
