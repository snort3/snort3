
set ( RNA_SOURCES
    rna_event_handler.cc
    rna_event_handler.h
    rna_inspector.cc
    rna_inspector.h
    rna_module.cc
    rna_module.h
)

#if (STATIC_INSPECTORS)
add_library( rna OBJECT
    ${RNA_SOURCES}
    )
#else (STATIC_INSPECTORS)
#   add_dynamic_module(rna inspectors
#       ${RNA_SOURCES}
#   )
#endif (STATIC_INSPECTORS)
