

add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)


if (ENABLE_NON_ETHER_DECODERS)
    set( NON_ETHER_DECODERS
        prot_eap.h
        prot_eap.cc
        prot_eapol.h
        prot_eapol.cc
        prot_eapolkey.h
        prot_eapolkey.cc
        prot_ipx.h
        prot_ipx.cc
    )
endif(ENABLE_NON_ETHER_DECODERS)


add_library( codecs STATIC
    encode.h
    encode.cc
    decode.h
    decode.cc
    decode_module.h
    decode_module.cc
    codec_api.h
    codec_api.cc
    ipv6_util.h
    ipv6_util.cc
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

