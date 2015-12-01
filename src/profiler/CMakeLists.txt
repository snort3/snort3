set ( PROFILER_INCLUDES profiler.h
    profiler_defs.h
    time_profiler_defs.h
    rule_profiler_defs.h
    )

set ( PROFILER_SOURCES profiler.cc
    profiler_nodes.h
    profiler_nodes.cc
    time_profiler.h
    time_profiler.cc
    rule_profiler.h
    rule_profiler.cc
    profiler_stats_table.cc
    profiler_stats_table.h
    profiler_builder.h
    )

add_library ( profiler STATIC
    ${PROFILER_SOURCES}
    ${PROFILER_INCLUDES}
)

install (FILES ${PROFILER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/profiler"
)
