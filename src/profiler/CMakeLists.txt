set ( PROFILER_SOURCES profiler.cc )
set ( PROFILER_INCLUDES profiler.h )

if ( ENABLE_PERFPROFILING )

    add_library ( profiler STATIC
        ${PROFILER_SOURCES}
        ${PROFILER_INCLUDES}
    )

endif ( ENABLE_PERFPROFILING )

install (FILES ${PROFILER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/profiler"
)
