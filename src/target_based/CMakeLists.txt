
add_library( target_based STATIC
    sftarget_reader.cc 
    sftarget_reader.h
    sftarget_hostentry.cc
    sftarget_hostentry.h
    sftarget_data.h
    snort_protocols.cc
)

set ( TARGET_BASED_INCLUDES
    snort_protocols.h
    )

install (FILES ${TARGET_BASED_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/target_based"
)
