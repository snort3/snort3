

add_subdirectory(basic)
add_subdirectory(plugins)


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
    checksum.h
    checksum.cc
)


target_link_libraries( codecs
    basic_codecs
    codec_plugins
    protocols
    sfip
    framework
    main
)

