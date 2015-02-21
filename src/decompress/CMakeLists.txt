
add_library (decompress STATIC
    file_decomp.cc
    file_decomp.h
    file_decomp_pdf.cc
    file_decomp_pdf.h
    file_decomp_swf.cc
    file_decomp_swf.h
)


target_link_libraries(decompress
    log
    utils
)
