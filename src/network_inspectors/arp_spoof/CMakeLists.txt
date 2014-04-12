
set(FILE_LIST
    arp_spoof.cc
    arp_module.cc
    arp_module.h
)

if (STATIC_INSPECTORS)
    add_library(arp_spoof STATIC
        ${FILE_LIST}
    )

else ()
    add_shared_library(arpspoof inspectors ${FILE_LIST})
    
endif ()