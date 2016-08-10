
set( DECOMPRESS_INCLUDES
    file_decomp.h
    file_decomp_pdf.h
    file_decomp_swf.h
)

add_library (decompress STATIC
    ${DECOMPRESS_INCLUDES}
    file_decomp.cc
    file_decomp_pdf.cc
    file_decomp_swf.cc
)

target_link_libraries(decompress
    log
    utils
)

install (FILES ${DECOMPRESS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/decompress"
)
