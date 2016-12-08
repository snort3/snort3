
if ( BUILD_SNPRINTF )
    SET (SNPRINTF_SOURCES
        snprintf.cc 
        snprintf.h c
        defs.h
    )
endif ( BUILD_SNPRINTF )

set( UTIL_INCLUDES
    bitop.h
    cpp_macros.h
    dnet_header.h
    kmap.h
    safec.h
    segment_mem.h
    sflsq.h
    sfmemcap.h
    sfsnprintfappend.h
    snort_bounds.h
    stats.h
    util.h
    util_jsnorm.h
    util_unfold.h
    util_utf.h
)

if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES bitop_test.cc)
endif()

ADD_LIBRARY( utils STATIC
    ${UTIL_INCLUDES}
    ${SNPRINTF_SOURCES}
    boyer_moore.cc 
    boyer_moore.h
    dyn_array.cc
    dyn_array.h
    kmap.cc
    segment_mem.cc 
    sflsq.cc 
    sfmemcap.cc 
    sfsnprintfappend.cc 
    stats.cc
    util.cc
    util_jsnorm.cc 
    util_net.cc 
    util_net.h
    util_unfold.cc 
    util_utf.cc 
    ${TEST_FILES}
)

target_link_libraries(utils
    log
)

install (FILES ${UTIL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/utils"
)

