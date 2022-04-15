
set (
    UNBUILT_SOURCES
    active.txt
    appid.txt
    binder.txt
    byte_extract.txt
    byte_jump.txt
    byte_math.txt
    byte_options.txt
    byte_test.txt
    concepts.txt
    connectors.txt
    dump_config.txt
    daq.txt
    dcerpc.txt
    errors.txt
    features.txt
    file_processing.txt
    ftp.txt
    high_availability.txt
    http_inspect.txt
    http2_inspect.txt
    iec104.txt
    mms.txt
    overview.txt
    params.txt
    perf_monitor.txt
    pop_imap.txt
    port_scan.txt
    sensitive_data.txt
    side_channel.txt
    smtp.txt
    snort2x.png
    snort3x.png
    snort_user.txt
    snorty.png
    telnet.txt
    terms.txt
    trace.txt
    tutorial.txt
    usage.txt
    wizard.txt
)

set (
    DEFAULT_MANUALS
    snort_user.text
)

foreach ( file_name ${UNBUILT_SOURCES} )
    list (
        APPEND
        LIST_DIR_SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/${file_name}"
    )
endforeach ( file_name )

add_custom_command (
    OUTPUT version.txt
    COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -o "Version.*$" > version.txt
    COMMAND sed -i -e "s/Version/:revnumber:/" version.txt
    DEPENDS snort
    COMMENT "Documents: building version.txt"
)

list ( APPEND BUILT_SOURCES version.txt )

foreach ( file_name ${BUILT_SOURCES} )
    list (
        APPEND
        BINARY_DIR_BUILT_SOURCES
        "${CMAKE_CURRENT_BINARY_DIR}/${file_name}"
    )
endforeach ( file_name )

add_custom_target (
    usr_built_sources
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
        OUTPUT snort_user.html snort_online.html
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} ./
        COMMAND ${ASCIIDOC_EXE} ${HTML_ASCIIDOC_ARGS} snort_user.txt
        COMMAND ${CMAKE_CURRENT_LIST_DIR}/online_manual.sh
        COMMAND mv snort_user.html snort_online.html ../
        DEPENDS usr_built_sources "${HTML_DOC_TMP}/"
        WORKING_DIRECTORY ${HTML_DOC_TMP}
        COMMENT "Documents: building snort_user.html and snort_online.html"
    )

    set ( TGZ_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/tgz/" )

    add_custom_command (
        OUTPUT "${TGZ_DOC_TMP}/"
        COMMAND mkdir -p ${TGZ_DOC_TMP}
    )

    add_custom_command (
        OUTPUT snort_user.tgz
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} ./
        COMMAND ${ASCIIDOC_A2X_EXE} ${HTML_A2X_ARGS} snort_user.txt
        COMMAND tar zcf ../snort_user.tgz snort_user.chunked
        DEPENDS usr_built_sources "${TGZ_DOC_TMP}/"
        WORKING_DIRECTORY ${TGZ_DOC_TMP}
        COMMENT "Documents: building snort_user.tgz"
    )

    add_custom_target (
        docs-user-html
        DEPENDS snort_user.html snort_user.tgz
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
        OUTPUT snort_user.text
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} ./
        COMMAND ${ASCIIDOC_A2X_EXE} ${TEXT_A2X_ARGS} snort_user.txt
        COMMAND mv snort_user.text ../
        DEPENDS usr_built_sources "${TEXT_DOC_TMP}/"
        WORKING_DIRECTORY ${TEXT_DOC_TMP}
        COMMENT "Documents: building snort_user.text"
    )

    add_custom_target (
        docs-user-text
        DEPENDS snort_user.text
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
        OUTPUT snort_user.pdf
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} ./
        COMMAND ${ASCIIDOC_A2X_EXE} ${PDF_A2X_ARGS} snort_user.txt
        COMMAND mv snort_user.pdf ../
        DEPENDS usr_built_sources "${PDF_DOC_TMP}/"
        WORKING_DIRECTORY ${PDF_DOC_TMP}
        COMMENT "Documents: building snort_user.pdf"
    )

    add_custom_target (
        docs-user-pdf
        DEPENDS snort_user.pdf
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

