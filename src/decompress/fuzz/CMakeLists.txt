add_fuzzer( file_decomp_zip_fuzz
    SOURCES ../file_decomp_zip.cc
    ../file_decomp_pdf.cc
    ../file_decomp_swf.cc
    ../file_decomp.cc
    ../../helpers/boyer_moore_search.cc
)

add_fuzzer( file_olefile_fuzz
    SOURCES ../file_olefile.cc
    ../file_oleheader.cc
    ../../helpers/boyer_moore_search.cc
    ../../helpers/utf.cc
)

