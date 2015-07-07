set (
    PP_DEFAULT_SOURCES
    piglet_plugins.cc
    piglet_plugins.h
    piglet_plugin_common.cc
    piglet_plugin_common.h
)


if (STATIC_PIGLETS)

    include (pp_static_sources.cmake)

    add_library (
        piglet_plugins STATIC
        ${PP_DEFAULT_SOURCES}
        ${PP_STATIC_SOURCES}
    )

else (STATIC_PIGLETS)

    add_library (
        piglet_plugins STATIC
        ${PP_DEFAULT_SOURCES}
    )

    include (pp_shared_libraries.cmake)

endif (STATIC_PIGLETS)
