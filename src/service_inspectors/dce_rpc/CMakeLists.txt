
set( FILE_LIST
   dce2_co.h 
   dce2_common.cc 
   dce2_common.h 
   dce2_list.h
   dce2_list.cc
   dce2_smb.cc 
   dce2_smb.h 
   dce2_smb_module.cc 
   dce2_smb_module.h 
   dce2_tcp.cc
   dce2_tcp.h 
   dce2_tcp_module.cc 
   dce2_tcp_module.h 
   dce2_utils.cc
   dce2_utils.h
   ips_dce2_iface.cc
   ips_dce2_opnum.cc
   ips_dce2_stub_data.cc

)

if (STATIC_INSPECTORS)

    add_library(dce_rpc STATIC ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_shared_library(dce_rpc inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
