
add_executable( u2spewfoo
    u2spewfoo.cc
    u2_common.h
)

target_include_directories( u2spewfoo
    PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

install (TARGETS u2spewfoo
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

