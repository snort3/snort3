if ( HAVE_SAFEC )
    set(RPC_DECODE_TEST_LIBS ${SAFEC_LIBRARIES})
endif ()

add_cpputest( rpc_decode_test
    SOURCES
        ../rpc_module.cc
        ../../../framework/module.cc
    LIBS
        ${RPC_DECODE_TEST_LIBS}
)
