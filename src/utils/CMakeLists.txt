find_package(Threads REQUIRED)

# FIXIT-M  remove.
add_definitions(" -std=c++11 -DHAVE_PTHREADS  ")

if ( BUILD_SNPRINTF )
    SET (SNPRINTF_SOURCES
        snprintf.cc 
        snprintf.h c
        defs.h
    )
endif ( BUILD_SNPRINTF )


set( UTIL_INCLUDES
    bitop.h
    dnet_header.h
    safec.h
    segment_mem.h
    sflsq.h
    sfmemcap.h
    snort_bounds.h
    stats.h
    util.h
)

ADD_LIBRARY( utils STATIC
    ${UTIL_INCLUDES}
    ${SNPRINTF_SOURCES}
    boyer_moore.cc 
    boyer_moore.h
    dyn_array.cc
    dyn_array.h
    kmap.cc
    kmap.h
    segment_mem.cc 
    sflsq.cc 
    sfmemcap.cc 
    sfsnprintfappend.cc 
    sfsnprintfappend.h
    stats.cc
    util.cc
    util_jsnorm.cc 
    util_jsnorm.h
    util_math.cc 
    util_math.h
    util_net.cc 
    util_net.h
    util_utf.cc 
    util_utf.h
    util_unfold.cc 
    util_unfold.h
)

target_link_libraries(utils
    log
)

install (FILES ${UTIL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/utils"
)

add_subdirectory ( test )
