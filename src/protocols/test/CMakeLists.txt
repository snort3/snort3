add_cpputest( get_geneve_opt_test
    SOURCES
        ../packet.cc
)

add_cpputest( ssl_protocol_test )
add_cpputest( ssl_parse_test
    LIBS
        ${OPENSSL_CRYPTO_LIBRARY}
)