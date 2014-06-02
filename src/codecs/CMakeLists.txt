

add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)


add_library( codecs STATIC
    decode.h
    decode_module.h
    codec_api.h
    codec_api.cc
    ipv6_util.h
    ipv6_util.cc
    codec_events.cc
    codec_events.h
    checksum.h
    checksum.cc
)


target_link_libraries( codecs
    root_codecs
    link_codecs
    ip_codecs
    misc_codecs
    protocols
    sfip
    framework
    main
)
