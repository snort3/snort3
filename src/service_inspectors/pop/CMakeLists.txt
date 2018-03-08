
set( FILE_LIST
    pop.cc
    pop.h
    pop_paf.cc
    pop_paf.h
    pop_config.h
    pop_module.cc
    pop_module.h
)

# can't be be linked dynamically yet
#if (STATIC_INSPECTORS)
    add_library( pop OBJECT ${FILE_LIST})

#else (STATIC_INSPECTORS)
    #add_dynamic_module(pop inspectors ${FILE_LIST})

#endif (STATIC_INSPECTORS)

