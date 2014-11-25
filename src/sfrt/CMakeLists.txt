

set ( SFRT_INCLUDES
    sfrt.h
    sfrt_trie.h
    sfrt_dir.h
    sfrt_flat.h
    sfrt_flat_dir.h
)

add_library ( sfrt STATIC
    sfrt.cc
    sfrt_dir.cc
    sfrt_flat.cc
    sfrt_flat_dir.cc
    ${SFRT_INCLUDES}
)

install (FILES ${SFRT_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/sfrt"
)
