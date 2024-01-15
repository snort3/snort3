
set (
    HELP_SOURCES
    commands.txt
    config.txt
    counts.txt
    modules.txt
    plugins.txt
    options.txt
    signals.txt
    help.txt
)

set (
    LIST_SOURCES
    gids.txt
)

set (
    MODULE_SOURCES
    basic.txt
    codec.txt
    connector.txt
    data.txt
    inspector.txt
    ips_action.txt
    ips_option.txt
    logger.txt
)

set (
    UNBUILT_SOURCES
    appendix.txt
    building.txt
    builtin_stubs.txt
    enviro.txt
    snort_reference.txt
)

set (
    DEFAULT_MANUALS
    snort_reference.text
)

function ( add_help_command generator_script output_file )
    add_custom_command (
        OUTPUT ${output_file}
        COMMAND ${generator_script} $<TARGET_FILE:snort> ${output_file} $ENV{SNORT_PLUGIN_PATH}
        DEPENDS snort
        COMMENT "Documents: building ${output_file}"
    )
endfunction ( add_help_command )

foreach ( output_file ${HELP_SOURCES} )
    add_help_command (
        "${CMAKE_CURRENT_LIST_DIR}/scripts/generate_help.sh"
        "${output_file}"
    )
    list ( APPEND BUILT_SOURCES "${output_file}" )
endforeach ()

foreach ( output_file ${LIST_SOURCES} )
    add_help_command (
        "${CMAKE_CURRENT_LIST_DIR}/scripts/generate_list.sh"
        "${output_file}"
    )
    list ( APPEND BUILT_SOURCES "${output_file}" )
endforeach ()

foreach ( output_file ${MODULE_SOURCES} )
    add_help_command (
        "${CMAKE_CURRENT_LIST_DIR}/scripts/generate_module.sh"
        "${output_file}"
    )
    list ( APPEND BUILT_SOURCES "${output_file}" )
endforeach ()

add_custom_command (
    OUTPUT version.txt
    COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -o "Version.*$" > version.txt
    COMMAND sed -i -e "s/Version/:revnumber:/" version.txt
    DEPENDS snort
    COMMENT "Documents: building version.txt"
)
list ( APPEND BUILT_SOURCES version.txt )

add_custom_command (
    OUTPUT builtin.txt
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/scripts/generate_builtin.sh $<TARGET_FILE:snort> ${CMAKE_CURRENT_LIST_DIR}/builtin_stubs.txt builtin.txt $ENV{SNORT_PLUGIN_PATH} 
    DEPENDS snort
    COMMENT "Documents: building builtin.txt"
)
list ( APPEND BUILT_SOURCES builtin.txt )

foreach ( file_name ${BUILT_SOURCES} )
    list (
        APPEND
        BINARY_DIR_BUILT_SOURCES
        "${CMAKE_CURRENT_BINARY_DIR}/${file_name}"
    )
endforeach ( file_name )

foreach ( file_name ${UNBUILT_SOURCES} )
    list (
        APPEND
        LIST_DIR_SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/${file_name}"
    )
endforeach ( file_name )

add_custom_target (
    ref_built_sources
    DEPENDS ${BUILT_SOURCES}
)

if ( MAKE_HTML_DOC )
    set (
        HTML_ASCIIDOC_ARGS
        -b xhtml11 -a toc2 -a icons -a imagesdir=.
    )

    set (
        HTML_A2X_ARGS
        --format=chunked
        --attribute=linkcss --attribute=stylesdir --attribute=disable-javascript
        --xsltproc-opts=\"--stringparam chunk.tocs.and.lots 1\"
        --attribute=quirks! --attribute=imagesdir=.
        --resource=.
    )

    set ( HTML_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/html/" )

    add_custom_command (
        OUTPUT "${HTML_DOC_TMP}/"
        COMMAND mkdir -p ${HTML_DOC_TMP}
    )

    add_custom_command (
        OUTPUT snort_reference.html
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_EXE} ${HTML_ASCIIDOC_ARGS} snort_reference.txt
        COMMAND mv snort_reference.html ../
        DEPENDS ref_built_sources "${HTML_DOC_TMP}/"
        WORKING_DIRECTORY ${HTML_DOC_TMP}
        COMMENT "Documents: building snort_reference.html"
    )

    add_custom_target (
        docs-reference-html
        DEPENDS snort_reference.html
    )

    foreach ( file_name ${UNBUILT_SOURCES} )
        list (
        APPEND
        BINARY_DIR_UNBUILT_SOURCES
        "${CMAKE_CURRENT_BINARY_DIR}/${file_name}"
        )
    endforeach ( file_name )

endif ( MAKE_HTML_DOC )

if ( MAKE_TEXT_DOC )
    set (
        TEXT_A2X_ARGS
        --format=text
    )

    set ( TEXT_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/text" )

    add_custom_command (
        OUTPUT "${TEXT_DOC_TMP}/"
        COMMAND mkdir -p ${TEXT_DOC_TMP}
    )

    add_custom_command (
        OUTPUT snort_reference.text
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_A2X_EXE} ${TEXT_A2X_ARGS} snort_reference.txt
        COMMAND mv snort_reference.text ../
        DEPENDS ref_built_sources "${TEXT_DOC_TMP}/"
        WORKING_DIRECTORY ${TEXT_DOC_TMP}
        COMMENT "Documents: building snort_reference.text"
    )

    add_custom_target (
        docs-reference-text
        DEPENDS snort_reference.text
    )

endif ( MAKE_TEXT_DOC )

if ( MAKE_PDF_DOC )
    set (
        PDF_A2X_ARGS
        --format=pdf
        --attribute=imagesdir=.
    )

    set ( PDF_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/pdf" )

    add_custom_command (
        OUTPUT "${PDF_DOC_TMP}/"
        COMMAND mkdir -p ${PDF_DOC_TMP}
    )

    add_custom_command (
        OUTPUT snort_reference.pdf
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_A2X_EXE} ${PDF_A2X_ARGS} snort_reference.txt
        COMMAND mv snort_reference.pdf ../
        DEPENDS ref_built_sources "${PDF_DOC_TMP}/"
        WORKING_DIRECTORY ${PDF_DOC_TMP}
        COMMENT "Documents: building snort_reference.pdf"
    )

    add_custom_target (
        docs-reference-pdf
        DEPENDS snort_reference.pdf
    )

endif ( MAKE_PDF_DOC )

install (
    FILES
    ${UNBUILT_SOURCES}
    ${DEFAULT_MANUALS}
    DESTINATION
    ${CMAKE_INSTALL_DOCDIR}
)

set (
    EXTRA_CLEAN
    ${EXTRA_CLEAN}
    ${BINARY_DIR_BUILT_SOURCES}
)

if ( NOT CMAKE_CURRENT_LIST_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR )
    list (
        APPEND
        EXTRA_CLEAN
        ${BINARY_DIR_UNBUILT_SOURCES}
    )
endif ()

if ( EXTRA_CLEAN )
    set_property (
        DIRECTORY
        PROPERTY
        ADDITIONAL_MAKE_CLEAN_FILES ${EXTRA_CLEAN}
    )
endif ( EXTRA_CLEAN )

