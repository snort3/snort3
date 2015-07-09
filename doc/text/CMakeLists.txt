set (
    TEXT_A2X_ARGS
    --format=text
    --resource=..
    --keep-artifacts # FIXIT: Do we need keep the build artifacts?
    )

add_custom_command (
    OUTPUT snort_manual.text
    COMMAND ${ASCIIDOC_A2X_EXE} ${TEXT_A2X_ARGS} ${SNORT_MANUAL_TXT}
    COMMAND cp ${DOC_BINARY_DIR}/snort_manual.text .
    DEPENDS all_doc_sources
    COMMENT "Documents: building snort_manual.text"
    )

add_custom_target (
    snort_manual_text
    DEPENDS snort_manual.text
    )

add_dependencies ( snort_manuals snort_manual_text )
