


set (FILE_LIST
    ft_module.cc
    ft_module.h
    ftp_telnet.cc
    ftp_bounce_lookup.cc 
    ftp_bounce_lookup.h
    ftp_client.h
    ftp_cmd_lookup.cc
    ftp_cmd_lookup.h
    ftpp_include.h
    ftpp_return_codes.h
    ftpp_si.cc 
    ftpp_si.h
    ftpp_ui_config.cc
    ftpp_ui_config.h
    ftp_server.h
    hi_util_kmap.cc
    hi_util_kmap.h
    hi_util_xmalloc.cc
    hi_util_xmalloc.h
    pp_ftp.cc 
    pp_ftp.h
    pp_telnet.cc 
    pp_telnet.h
    ftpp_util_kmap.h
    ft_main.h
    ft_main.cc
)


if (STATIC_INSPECTORS)
    add_library(ftp_telnet STATIC ${FILE_LIST})
    target_link_libraries(ftp_telnet
        utils
    )

else ()
   add_shared_library(ftp_telnet inspectors ${FILE_LIST})

endif ()


