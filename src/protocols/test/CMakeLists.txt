add_cpputest( get_geneve_opt_test
    SOURCES
        ../packet.cc
)

add_cpputest( decode_err_len_test
  SOURCES
      ../packet.cc
      ../packet_manager.cc
)

add_cpputest( ssl_protocol_test )