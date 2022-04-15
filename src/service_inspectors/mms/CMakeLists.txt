
set( FILE_LIST
    mms.cc
    mms.h
    mms_decode.cc
    mms_decode.h
    mms_module.cc
    mms_module.h
    mms_splitter.cc
    mms_splitter.h
    ips_mms_data.cc
    ips_mms_func.cc
    tpkt/tpkt_decode.cc
    tpkt/tpkt_decode.h
    tpkt/cotp_decode.cc
    tpkt/cotp_decode.h
    tpkt/osi_session_decode.cc
    tpkt/osi_session_decode.h
    tpkt/osi_pres_decode.cc
    tpkt/osi_pres_decode.h
    tpkt/osi_acse_decode.cc
    tpkt/osi_acse_decode.h
    util_tpkt.cc
    util_tpkt.h
)

if (STATIC_INSPECTORS)
    add_library(mms OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(mms inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

