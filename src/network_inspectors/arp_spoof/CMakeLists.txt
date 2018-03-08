
set(FILE_LIST
    arp_spoof.cc
    arp_module.cc
    arp_module.h
)

if (STATIC_INSPECTORS)
    add_library(arp_spoof OBJECT
        ${FILE_LIST}
    )

else (STATIC_INSPECTORS)
    add_dynamic_module(arp_spoof inspectors ${FILE_LIST})
    
endif (STATIC_INSPECTORS)
