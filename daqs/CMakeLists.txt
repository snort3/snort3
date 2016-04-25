macro ( add_daq_module libname )
    set ( sources ${ARGN} )
    add_library ( ${libname} MODULE ${sources} )
    set_target_properties (
        ${libname}
        PROPERTIES
            COMPILE_FLAGS "-DBUILDING_SO"
            C_STANDARD 99
    )

    install (
        TARGETS ${libname}
        LIBRARY
        DESTINATION "lib/${CMAKE_PROJECT_NAME}/daqs"
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
