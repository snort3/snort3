
set( UTIL_INCLUDES
    boyer_moore.h
    cpp_macros.h
    endian.h
    event_gen.h
    infractions.h
    kmap.h
    memcap_allocator.h
    primed_allocator.h
    safec.h
    sflsq.h
    stats.h
    util.h
    util_ber.h
    util_cstring.h
    util_unfold.h
    util_utf.h
    util_numa.h
)

add_library ( utils OBJECT
    ${UTIL_INCLUDES}
    ${SNPRINTF_SOURCES}
    boyer_moore.cc
    dnet_header.h
    dyn_array.cc
    dyn_array.h
    kmap.cc
    sflsq.cc
    snort_bounds.h
    stats.cc
    streambuf.cc
    streambuf.h
    util.cc
    util_ber.cc
    util_cstring.cc
    util_jsnorm.cc
    util_jsnorm.h
    util_net.cc
    util_net.h
    util_unfold.cc
    util_utf.cc
    util_numa.h
    ${TEST_FILES}
)

install (FILES ${UTIL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/utils"
)

add_subdirectory(test)

