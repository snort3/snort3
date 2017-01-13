macro ( add_daq_module libname )
    add_dynamic_module ( ${libname} daqs ${ARGN} )
    set_target_properties (
        ${libname}
        PROPERTIES
            C_STANDARD 99
    )
endmacro ( add_daq_module )

set ( DAQS_INCLUDES daq_user.h )
set(
    EXTERNAL_INCLUDES
    ${DAQ_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${DNET_INCLUDE_DIR}
)

include_directories ( AFTER ${EXTERNAL_INCLUDES} )

add_daq_module ( daq_file daq_file.c )
add_daq_module ( daq_hext daq_hext.c )

install (FILES ${DAQS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/daqs"
)
