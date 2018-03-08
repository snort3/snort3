set( FILE_LIST
    modbus.cc
    modbus.h
    modbus_decode.cc
    modbus_decode.h
    modbus_module.cc
    modbus_module.h
    modbus_paf.cc
    modbus_paf.h
    ips_modbus_data.cc
    ips_modbus_func.cc
    ips_modbus_unit.cc
)

if (STATIC_INSPECTORS)
    add_library(modbus OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(modbus inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

