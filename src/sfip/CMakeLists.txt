
set(SFIP_INCLUDES
    sf_cidr.h
    sf_ip.h
    sf_returns.h
)

if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES sfip_test.cc)
endif()

add_library ( sfip OBJECT
    ${SFIP_INCLUDES}
    ${TEST_FILES}
    sf_cidr.cc
    sf_ip.cc
    sf_ipvar.cc
    sf_ipvar.h
    sf_vartable.cc
    sf_vartable.h 
)

install (FILES ${SFIP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/sfip"
)
