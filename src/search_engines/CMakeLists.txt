
set (SEARCH_ENGINE_INCLUDES
    search_common.h
    search_tool.h
)

set (ACSMX2_SOURCES
    ac_full.cc
    acsmx2.cc
    acsmx2.h
)

set (BNFA_SOURCES
    ac_bnfa.cc
    bnfa_search.cc
    bnfa_search.h
)

if ( HAVE_HYPERSCAN )
    set(HYPER_SOURCES
        hyperscan.cc
    )
endif ()

set (SEARCH_ENGINE_SOURCES
    pat_stats.h
    search_engines.cc
    search_engines.h
    search_tool.cc
    ${BNFA_SOURCES}
    ${ACSMX2_SOURCES}
)

if ( STATIC_SEARCH_ENGINES )
    add_library(search_engines OBJECT
        ${HYPER_SOURCES}
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
    )

else ( STATIC_SEARCH_ENGINES)
    add_library(search_engines OBJECT
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
    )

if ( HAVE_HYPERSCAN )
    add_dynamic_module(hyperscan search_engines ${HYPER_SOURCES})
endif ()

endif (STATIC_SEARCH_ENGINES)


install(FILES ${SEARCH_ENGINE_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/search_engines"
)

add_subdirectory(test)
