

add_custom_target(sid_18758.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_sid sid_18758.h
)

add_example_library(18758 so_rules sid_18758.cc sid_18758.h)
