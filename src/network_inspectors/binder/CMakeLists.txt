
set(FILE_LIST
    binder.cc
    binding.h
    bind_module.cc
    bind_module.h
)

#if (STATIC_INSPECTORS)
add_library(binder OBJECT ${FILE_LIST})

#else (STATIC_INSPECTORS)
#    add_dynamic_module(binder inspectors ${FILE_LIST})
#    
#endif (STATIC_INSPECTORS)

