
set(FILE_LIST
    binder.cc
    binding.h
    bind_module.cc
    bind_module.h
)

#if (STATIC_INSPECTORS)
    add_library(binder STATIC ${FILE_LIST})

#else (STATIC_INSPECTORS)
#    add_shared_library(binder inspectors ${FILE_LIST})
#    
#endif (STATIC_INSPECTORS)
