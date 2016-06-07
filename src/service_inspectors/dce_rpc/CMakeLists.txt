
set( FILE_LIST
   dce_co.cc
   dce_co.h 
   dce_common.cc 
   dce_common.h 
   dce_list.h
   dce_list.cc
   dce_smb.cc 
   dce_smb.h
   dce_smb_commands.cc
   dce_smb_commands.h 
   dce_smb_module.cc 
   dce_smb_module.h 
   dce_smb_paf.cc 
   dce_smb_paf.h
   dce_smb_utils.cc
   dce_smb_utils.h
   dce_tcp.cc
   dce_tcp.h 
   dce_tcp_module.cc 
   dce_tcp_module.h 
   dce_tcp_paf.cc 
   dce_tcp_paf.h 
   dce_utils.cc
   dce_utils.h
   ips_dce_iface.cc
   ips_dce_opnum.cc
   ips_dce_stub_data.cc

)

if (STATIC_INSPECTORS)

    add_library(dce_rpc STATIC ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_shared_library(dce_rpc inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
