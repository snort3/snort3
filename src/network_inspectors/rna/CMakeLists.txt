set (RNA_INCLUDES
    rna_fingerprint.h
    rna_fingerprint_smb.h
    rna_fingerprint_tcp.h
    rna_fingerprint_ua.h
    rna_fingerprint_udp.h
    rna_flow.h
    rna_inspector.h
    rna_logger.h
    rna_name.h
    rna_cpe_os.h
)

set ( RNA_SOURCES
    ${RNA_INCLUDES}
    data_purge_cmd.cc
    data_purge_cmd.h
    rna_app_discovery.cc
    rna_app_discovery.h
    rna_event_handler.cc
    rna_event_handler.h
    rna_fingerprint.cc
    rna_fingerprint_smb.cc
    rna_fingerprint_tcp.cc
    rna_fingerprint_ua.cc
    rna_fingerprint_udp.cc
    rna_inspector.cc
    rna_flow.cc
    rna_logger.cc
    rna_logger_common.h
    rna_mac_cache.cc
    rna_mac_cache.h
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

add_subdirectory(test)
