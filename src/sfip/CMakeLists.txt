
set(SFIP_INCLUDES
    sf_cidr.h
    sf_ip.h
    sf_returns.h
)

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

add_subdirectory(test)
