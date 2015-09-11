
set(EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
    CACHE INTERNAL "external INCLUDES" FORCE
)

include_directories(AFTER ${EXTERNAL_INCLUDES})

add_shared_library(daq_socket daqs daq_socket.c daq_socket.h)
add_shared_library(daq_file daqs daq_file.c daq_socket.h)
add_shared_library(daq_hext daqs daq_hext.c daq_socket.h)

