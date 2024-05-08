
set( UTIL_INCLUDES
    bits.h
    cpp_macros.h
    endian.h
    safec.h
    util.h
    util_cstring.h
    util_unfold.h
)

add_library ( utils OBJECT
    ${UTIL_INCLUDES}
    ${SNPRINTF_SOURCES}
    chunk.cc
    chunk.h
    dnet_header.h
    sflsq.cc
    sflsq.h
    snort_bounds.h
    stats.cc
    stats.h
    util.cc
    util_cstring.cc
    util_jsnorm.cc
    util_jsnorm.h
    util_net.cc
    util_net.h
    util_unfold.cc
    ${TEST_FILES}
)

install (FILES ${UTIL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/utils"
)

