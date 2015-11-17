set ( PROFILER_INCLUDES profiler.h )
set ( PROFILER_SOURCES profiler.cc )

add_library ( profiler STATIC
    ${PROFILER_SOURCES}
    ${PROFILER_INCLUDES}
)

install (FILES ${PROFILER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/profiler"
)
