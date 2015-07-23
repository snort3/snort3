
include_directories(${PROJECT_SOURCE_DIR}/src)

add_executable( u2spewfoo
    u2spewfoo.cc
    u2_common.h
)

install (TARGETS u2spewfoo
    RUNTIME DESTINATION bin
)

