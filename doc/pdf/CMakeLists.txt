set (
    PDF_A2X_ARGS
    --format=pdf
    --attribute=imagesdir=.
    --resource=..
    --destination-dir=.
    --keep-artifacts # FIXIT: Do we need keep the build artifacts?
    )

add_custom_command (
    OUTPUT snort_manual.pdf
    COMMAND ${ASCIIDOC_A2X_EXE} ${PDF_A2X_ARGS} ${SNORT_MANUAL_TXT}
    DEPENDS all_doc_sources
    COMMENT "Documents: building snort_manual.pdf"
    )

add_custom_target (
    snort_manual_pdf
    DEPENDS snort_manual.pdf
    )

add_dependencies ( snort_manuals snort_manual_pdf )
