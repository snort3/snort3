add_cpputest( get_geneve_opt_test
    SOURCES
        ../packet.cc
)

add_cpputest( encap_layer_test
    SOURCES
        ../layer.cc
        ../packet.cc
)

add_cpputest( encode_format_test
    SOURCES
        ../layer.cc
        ../packet.cc
        ../packet_manager.cc
)

add_cpputest( ssl_protocol_test )
add_cpputest( ssl_parse_test
    LIBS
        ${OPENSSL_CRYPTO_LIBRARY}
)