
if (ENABLE_NON_ETHER_DECODERS)
    set(NON_ETHER_DECODERS
        root_trk.h
        root_trk.cc
        root_fddi.h
        root_fddi.cc
        root_linuxsll.h
        root_linuxsll.cc
        root_ieee80211.h
        root_ieee80211.cc
        root_slip.h
        root_slip.cc
        root_i4lrawip.h
        root_i4lrawip.cc
        root_oldpflog.h
        root_oldpflog.cc
        root_enc.h
        root_enc.cc
        root_ppp.h
        root_ppp.cc
        root_pflog.h
        root_pflog.cc
        root_pppserial.h
        root_pppserial.cc
        root_chdlc.h
        root_chdlc.cc
        root_i4lciscoip.h
        root_i4lciscoip.cc
    )
endif (ENABLE_NON_ETHER_DECODERS)


add_library(root_decoders STATIC
    root_eth.cc
    root_eth.h
    root_null.h
    root_null.cc
    root_raw4.h
    root_raw4.cc
    root_raw6.h
    root_raw6.cc
    ${NON_ETHER_DECODERS}
    ../decoder_includes.h  #REMOVE!!!
)

target_link_libraries(root_decoders
    protocols
)
