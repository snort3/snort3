
add_library(lowmem SHARED
    lowmem.cc
    lowmem_q.cc
    pat_stats.cc
    sfksearch.cc
    sfksearch.h
    trie_api.cc
)

set_target_properties ( lowmem
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)

install (TARGETS lowmem
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/search_engines"
)
