
set( DECOMPRESS_INCLUDES
    file_decomp.h
)

add_library (decompress OBJECT
    ${DECOMPRESS_INCLUDES}
    file_decomp.cc
    file_decomp_pdf.cc
    file_decomp_pdf.h
    file_decomp_swf.cc
    file_decomp_swf.h
)

install (FILES ${DECOMPRESS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/decompress"
)
