
set( FILE_LIST
    dce_co.cc
    dce_co.h 
    dce_common.cc 
    dce_common.h 
    dce_context_data.cc 
    dce_context_data.h
    dce_http_proxy.cc
    dce_http_proxy_module.cc 
    dce_http_proxy_module.h 
    dce_http_proxy_splitter.cc 
    dce_http_proxy_splitter.h
    dce_http_server.cc
    dce_http_server_module.cc 
    dce_http_server_module.h 
    dce_http_server_splitter.cc 
    dce_http_server_splitter.h
    dce_list.h
    dce_list.cc
    dce_smb.cc 
    dce_smb.h
    dce_smb2.cc
    dce_smb2.h
    dce_smb_commands.cc
    dce_smb_commands.h 
    dce_smb_module.cc 
    dce_smb_module.h 
    dce_smb_paf.cc 
    dce_smb_paf.h
    dce_smb_transaction.cc
    dce_smb_transaction.h
    dce_smb_transaction_utils.cc
    dce_smb_transaction_utils.h
    dce_smb_utils.cc
    dce_smb_utils.h
    dce_tcp.cc
    dce_tcp.h 
    dce_tcp_module.cc 
    dce_tcp_module.h 
    dce_tcp_paf.cc 
    dce_tcp_paf.h
    dce_udp.cc
    dce_udp.h 
    dce_udp_module.cc 
    dce_udp_module.h
    dce_udp_processing.cc
    dce_utils.cc
    dce_utils.h
    ips_dce_iface.cc
    ips_dce_opnum.cc
    ips_dce_stub_data.cc
    smb_common.h
    smb_message.cc
    smb_message.h
)

if (STATIC_INSPECTORS)

    add_library(dce_rpc OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(dce_rpc inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
