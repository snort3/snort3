set (RNA_INCLUDES
    rna_logger.h
)

set ( RNA_SOURCES
    ${RNA_INCLUDES}
    rna_event_handler.cc
    rna_event_handler.h
    rna_inspector.cc
    rna_inspector.h
    rna_logger.cc
    rna_logger_common.h
    rna_module.cc
    rna_module.h
    rna_pnd.cc
    rna_pnd.h
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

install(FILES ${RNA_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/network_inspectors/rna"
)