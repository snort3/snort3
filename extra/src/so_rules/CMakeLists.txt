

add_custom_target(sid_18758.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_sid sid_18758.h
)

add_library( 18758 SHARED
    sid_18758.cc
    sid_18758.h
)

set_target_properties ( 18758
    PROPERTIES
    LINK_FLAGS "-export-dynamic -shared"
)


install (TARGETS 18758
    LIBRARY DESTINATION "${EX_INSTALL_PATH}/so_rules"
)
