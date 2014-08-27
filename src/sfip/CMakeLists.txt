

set(SFIP_INCLUDES
    sf_returns.h
    sf_ip.h
    sf_ipvar.h
    sfip_t.h
)

add_library ( sfip STATIC
    ${SFIP_INCLUDES}
    sf_ip.cc
    sf_ipvar.cc
    sf_vartable.cc
    sf_vartable.h 
)

install (FILES ${SFIP_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/sfip"
)
