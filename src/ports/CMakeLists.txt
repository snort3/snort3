
ADD_LIBRARY( ports STATIC
    port_group.cc
    port_group.h
    port_item.cc
    port_item.h
    port_object.cc
    port_object.h
    port_object2.cc
    port_object2.h
    port_table.cc
    port_table.h
    port_utils.cc
    port_utils.h
    port_var_table.cc
    port_var_table.h
    rule_port_tables.cc
    rule_port_tables.h
)

target_link_libraries(ports
    log
)

list(APPEND PACKAGED_DIST "readme.txt")

