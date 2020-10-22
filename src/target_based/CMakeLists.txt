
add_library( target_based OBJECT
    host_attributes.cc
    host_attributes.h
    snort_protocols.cc
)

set ( TARGET_BASED_INCLUDES
    snort_protocols.h
)

install (FILES ${TARGET_BASED_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/target_based"
)

add_subdirectory( test )
