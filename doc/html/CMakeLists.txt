set (
    HTML_ASCIIDOC_ARGS
    -b xhtml11
    -a toc2
    -a icons
    -a imagesdir=..
    )

set (
    HTML_A2X_ARGS
    --format=chunked
    --attribute=linkcss --attribute=stylesdir --attribute=disable-javascript
    --xsltproc-opts=\"--stringparam chunk.tocs.and.lots 1\"
    --attribute=quirks!
    --attribute=imagesdir=.
    --resource=..
    --destination-dir=.
    --keep-artifacts # FIXIT: Do we need keep the build artifacts?
    )

add_custom_command (
    OUTPUT snort_manual.chunked
    COMMAND ${ASCIIDOC_EXE} ${HTML_ASCIIDOC_ARGS} ${SNORT_MANUAL_TXT}
    COMMAND ${ASCIIDOC_A2X_EXE} ${HTML_A2X_ARGS} ${SNORT_MANUAL_TXT}
    DEPENDS all_doc_sources
    COMMENT "Documents: building snort_manual.html"
    )

add_custom_command (
    OUTPUT snort_manual.html
    COMMAND cp ${DOC_BINARY_DIR}/snort_manual.html .
    DEPENDS snort_manual.chunked
    )

add_custom_target (
    snort_manual_html
    DEPENDS snort_manual.html snort_manual.chunked
    )

add_dependencies ( snort_manuals snort_manual_html )
