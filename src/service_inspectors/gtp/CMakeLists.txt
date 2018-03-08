
set( FILE_LIST
    gtp.cc
    gtp.h
    gtp_inspect.cc
    gtp_inspect.h
    gtp_module.cc
    gtp_module.h
    gtp_parser.cc
    gtp_parser.h
    ips_gtp_info.cc
    ips_gtp_type.cc
    ips_gtp_version.cc
)

if (STATIC_INSPECTORS)
    add_library(gtp_inspect OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(gtp_inspect inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

