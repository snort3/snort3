
set (
    UNBUILT_SOURCES
    differences.txt
    overview.txt
    snort2lua.txt
    snort_upgrade.txt
)

set (
    DEFAULT_MANUALS
    snort_upgrade.text
)

add_custom_command (
    OUTPUT version.txt
    COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -o "Version.*$" > version.txt
    COMMAND sed -i -e "s/Version/:revnumber:/" version.txt
    COMMAND echo ":revdate: {localdate} {localtime}" >> version.txt
    DEPENDS snort
    COMMENT "Documents: building version.txt"
)
list ( APPEND BUILT_SOURCES version.txt )

add_custom_command (
    OUTPUT snort2lua_cmds.txt
    COMMAND $<TARGET_FILE:snort2lua> --markup --help > snort2lua_cmds.txt
    DEPENDS snort2lua
    COMMENT "Documents: building snort2lua_cmds.txt"
)
list ( APPEND BUILT_SOURCES snort2lua_cmds.txt )

if ( RUBY_EXECUTABLE )
    add_custom_command (
        OUTPUT config_changes.txt
        COMMAND ${RUBY_EXECUTABLE}
        "${CMAKE_CURRENT_LIST_DIR}/get_differences.rb"
        "${CMAKE_SOURCE_DIR}/tools/snort2lua"
        > "${CMAKE_CURRENT_BINARY_DIR}/config_changes.txt"
        DEPENDS snort2lua get_differences.rb
        COMMENT "Documents: building config_changes.txt"
    )
    list ( APPEND BUILT_SOURCES config_changes.txt )

else ( RUBY_EXECUTABLE )
    list ( APPEND UNBUILT_SOURCES config_changes.txt )

endif ( RUBY_EXECUTABLE )

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
    upg_built_sources
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
        OUTPUT snort_upgrade.html
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_EXE} ${HTML_ASCIIDOC_ARGS} snort_upgrade.txt
        COMMAND mv snort_upgrade.html ../
        DEPENDS upg_built_sources "${HTML_DOC_TMP}/"
        WORKING_DIRECTORY ${HTML_DOC_TMP}
        COMMENT "Documents: building snort_upgrade.html"
    )

    add_custom_target (
        docs-upgrade-html
        DEPENDS snort_upgrade.html
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
        OUTPUT snort_upgrade.text
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_A2X_EXE} ${TEXT_A2X_ARGS} snort_upgrade.txt
        COMMAND mv snort_upgrade.text ../
        DEPENDS upg_built_sources "${TEXT_DOC_TMP}/"
        WORKING_DIRECTORY ${TEXT_DOC_TMP}
        COMMENT "Documents: building snort_upgrade.text"
    )

    add_custom_target (
        docs-upgrade-text
        DEPENDS snort_upgrade.text
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
        OUTPUT snort_upgrade.pdf
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
        COMMAND ${ASCIIDOC_A2X_EXE} ${PDF_A2X_ARGS} snort_upgrade.txt
        COMMAND mv snort_upgrade.pdf ../
        DEPENDS upg_built_sources "${PDF_DOC_TMP}/"
        WORKING_DIRECTORY ${PDF_DOC_TMP}
        COMMENT "Documents: building snort_upgrade.pdf"
    )

    add_custom_target (
        docs-upgrade-pdf
        DEPENDS snort_upgrade.pdf
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

