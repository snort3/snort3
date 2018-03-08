
set (FILE_LIST
    ft_main.cc
    ft_main.h
    ftp.cc
    ftp_data.cc
    ftp_data.h
    ftp_bounce_lookup.cc
    ftp_bounce_lookup.h
    ftp_client.h
    ftp_cmd_lookup.cc
    ftp_cmd_lookup.h
    ftp_module.cc
    ftp_module.h
    ftp_parse.cc
    ftp_parse.h
    ftp_print.cc
    ftp_print.h
    ftp_server.h
    ftp_splitter.h
    ftp_splitter.cc
    ftpdata_splitter.h
    ftpdata_splitter.cc
    ftpp_return_codes.h
    ftpp_si.cc
    ftpp_si.h
    ftpp_ui_config.cc
    ftpp_ui_config.h
    pp_ftp.cc
    pp_ftp.h
    pp_telnet.cc
    pp_telnet.h
    telnet.cc
    telnet.h
    telnet_module.cc
    telnet_module.h
)

if (STATIC_INSPECTORS)
    add_library(ftp_telnet OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
   add_dynamic_module(ftp_telnet inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

