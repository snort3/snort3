
add_library( port_scan
    port_scan.cc
    ps_detect.cc
    ps_detect.h
    ps_inspect.h
    ps_module.cc
    ps_module.h
    ipobj.cc
    ipobj.h
)

target_link_libraries( port_scan
    events
)
