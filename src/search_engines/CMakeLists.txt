
set (SEARCH_ENGINE_INCLUDES
    search_common.h
    search_tool.h
)

set (ACSMX_SOURCES
    ac_std.cc 
    acsmx.cc
    acsmx.h
)

set (ACSMX2_SOURCES
    ac_banded.cc
    ac_full.cc
    ac_sparse.cc
    ac_sparse_bands.cc
    acsmx2.cc
    acsmx2.h
    acsmx2_api.cc
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
)

if ( STATIC_SEARCH_ENGINES )
    add_library(search_engines OBJECT
        ${ACSMX_SOURCES}
        ${ACSMX2_SOURCES}
        ${HYPER_SOURCES}
        ${INTEL_SOURCES}
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
    )

else ( STATIC_SEARCH_ENGINES)
    add_library(search_engines OBJECT
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
    )

    add_dynamic_module(acsmx search_engines ${ACSMX_SOURCES})
    add_dynamic_module(acsmx2 search_engines ${ACSMX2_SOURCES})
if ( HAVE_HYPERSCAN )
    add_dynamic_module(hyperscan search_engines ${HYPER_SOURCES})
endif ()

endif (STATIC_SEARCH_ENGINES)


install(FILES ${SEARCH_ENGINE_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/search_engines"
)

add_subdirectory(test)
