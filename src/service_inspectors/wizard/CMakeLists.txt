
set(FILE_LIST
    wizard.cc
    wizard.h
    wiz_module.cc
    wiz_module.h
)

#if (STATIC_INSPECTORS)
    add_library(wizard STATIC ${FILE_LIST})

#else (STATIC_INSPECTORS)
#    add_shared_library(wizard inspectors ${FILE_LIST})
#    
#endif (STATIC_INSPECTORS)

