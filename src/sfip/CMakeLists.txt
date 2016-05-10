
set(SFIP_INCLUDES
    sf_returns.h
    sf_ip.h
    sf_ipvar.h
    sfip_t.h
)

if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES sfip_test.cc)
endif()

add_library ( sfip STATIC
    ${SFIP_INCLUDES}
    ${TEST_FILES}
    sf_ip.cc
    sf_ipvar.cc
    sf_vartable.cc
    sf_vartable.h 
)

install (FILES ${SFIP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/sfip"
)
