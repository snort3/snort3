
set (SEARCH_ENGINE_INCLUDES
    pat_stats.h
)

set (ACSMX_SOURCES
    ac_std.cc 
    acsmx.cc
    acsmx.h
)

set (ACSMX2_SOURCES
    ac_banded.cc
    ac_full.cc
    ac_full_q.cc
    ac_sparse.cc
    ac_sparse_bands.cc
    acsmx2.cc
    acsmx2.h
)

set (BNFA_SOURCES
    ac_bnfa.cc
    ac_bnfa_q.cc
    bnfa_search.cc
    bnfa_search.h
)


if ( ENABLE_INTEL_SOFT_CPM )
    set(INTEL_SOURCES
        intel_cpm.cc 
        intel_soft_cpm.cc
        intel_soft_cpm.h
    )

endif (ENABLE_INTEL_SOFT_CPM)

set (PLUGIN_LIST
    ${ACSMX_SOURCES}
    ${ACSMX2_SOURCES}
    ${INTEL_SOURCES}
)


set (SEARCH_ENGINE_SOURCES
    search_common.h
    search_engines.cc
    search_engines.h
    search_tool.cc
    search_tool.h
    ${BNFA_SOURCES}
)

# FIXIT ideally don't include pat_stats.cc separately

if ( STATIC_SEARCH_ENGINES )
    add_library(search_engines STATIC
        ${ACSMX_SOURCES}
        ${ACSMX2_SOURCES}
        ${INTEL_SOURCES}
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
        pat_stats.cc
    )

else ( STATIC_SEARCH_ENGINES)
    add_library(search_engines STATIC
        ${SEARCH_ENGINE_SOURCES}
        ${SEARCH_ENGINE_INCLUDES}
        ${BNFA_SOURCES}
        pat_stats.cc
    )

    add_shared_library(acsmx search_engines ${ACSMX_SOURCES} pat_stats.cc)
    add_shared_library(acsmx2 search_engines ${ACSMX2_SOURCES} acsmx2_api.cc pat_stats.cc)
    add_shared_library(intel_cpm search_engines ${INTEL_SOURCES} pat_stats.cc)


endif (STATIC_SEARCH_ENGINES)


install(FILES ${SEARCH_ENGINE_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/search_engines"
)
