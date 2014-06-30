


set (FILE_LIST
    port_scan.cc
    ps_detect.cc
    ps_detect.h
    ps_inspect.h
    ps_module.cc
    ps_module.h
    ipobj.cc
    ipobj.h
)

if (STATIC_INSPECTORS)
    add_library( port_scan STATIC
        ${FILE_LIST}
    )
    target_link_libraries( port_scan
        events
    )


else (STATIC_INSPECTORS)
    add_shared_library(port_scan inspectors "${FILE_LIST}")

endif (STATIC_INSPECTORS)

