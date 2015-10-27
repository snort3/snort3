if ( ENABLE_PERFPROFILING )
    set ( PROFILER_SOURCES profiler.cc )
endif ( ENABLE_PERFPROFILING )
set ( PROFILER_INCLUDES profiler.h )

# FIXIT-L Should this be conditionally compiled as well?
set ( PPM_SOURCES ppm.cc ppm_module.cc ppm_module.h )
set ( PPM_INCLUDES ppm.h )

set ( TIME_INTERNAL_SOURCES
    packet_time.cc
    packet_time.h
    periodic.cc
    periodic.h
    timersub.h
    )

set ( TIME_INCLUDES
    ${PROFILER_INCLUDES}
    ${PPM_INCLUDES}
    cpuclock.h
    )

add_library ( time STATIC
    ${PROFILER_SOURCES}
    ${PPM_SOURCES}
    ${TIME_INTERNAL_SOURCES}
    ${TIME_INCLUDES}
    )

install (FILES ${TIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/time"
)
