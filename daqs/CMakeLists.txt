
set (DAQS_INCLUDES
    daq_user.h
)

set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    CACHE INTERNAL "external INCLUDES" FORCE
)

include_directories(AFTER ${EXTERNAL_INCLUDES})

add_shared_library(daq_file daqs daq_file.c daq_user.h)
add_shared_library(daq_hext daqs daq_hext.c daq_user.h)

set_property(TARGET daq_file PROPERTY C_STANDARD 99)
set_property(TARGET daq_hext PROPERTY C_STANDARD 99)

install (FILES ${DAQS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/daqs"
)
