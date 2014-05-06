
add_library( misc_codecs STATIC
    cd_gtp.cc
    cd_null.cc
    cd_teredo.cc
)


target_link_libraries( misc_codecs
    protocols
)