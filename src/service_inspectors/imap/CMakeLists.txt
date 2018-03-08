
set( FILE_LIST
    imap.cc
    imap.h
    imap_paf.cc
    imap_paf.h
    imap_config.h
    imap_module.cc
    imap_module.h
)

# can't be be linked dynamically yet
#if (STATIC_INSPECTORS)
    add_library( imap OBJECT ${FILE_LIST})

#else (STATIC_INSPECTORS)
    #add_dynamic_module(imap inspectors ${FILE_LIST})

#endif (STATIC_INSPECTORS)

