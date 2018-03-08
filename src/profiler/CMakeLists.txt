set ( PROFILER_INCLUDES
    memory_defs.h
    memory_context.h
    memory_profiler_defs.h
    profiler.h
    profiler_defs.h
    rule_profiler_defs.h
    time_profiler_defs.h
    )

set ( PROFILER_SOURCES
    active_context.h
    memory_context.cc
    memory_profiler.cc
    memory_profiler.h
    profiler.cc
    profiler_printer.h
    profiler_stats_table.cc
    profiler_stats_table.h
    profiler_tree_builder.h
    profiler_nodes.cc
    profiler_nodes.h
    rule_profiler.cc
    rule_profiler.h
    time_profiler.cc
    time_profiler.h
    )

add_library ( profiler OBJECT
    ${PROFILER_SOURCES}
    ${PROFILER_INCLUDES}
)

install (FILES ${PROFILER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/profiler"
)
