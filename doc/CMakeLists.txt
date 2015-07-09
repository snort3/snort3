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
    builtin.txt
    gids.txt
    )

set (
    MODULE_SOURCES
    basic.txt
    codec.txt
    data.txt
    inspector.txt
    ips_action.txt
    ips_option.txt
    logger.txt
    )

set (
    UNBUILT_SOURCES
    bugs.txt
    daq.txt
    differences.txt
    errors.txt
    enviro.txt
    extending.txt
    features.txt
    overview.txt
    params.txt
    reference.txt
    snort2lua.txt
    snorty.png
    snort2x.png
    snort3x.png
    snort_manual.txt
    start.txt
    style.txt
    terms.txt
    usage.txt
    )

include ( help.cmake )

add_custom_target ( snort_manuals ALL )

if ( MAKE_HTML_DOC OR MAKE_TEXT_DOC OR MAKE_PDF_DOC )
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
        COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -v Using > version.txt
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
                > config_changes.txt
            DEPENDS snort2lua get_differences.rb
            COMMENT "Documents: building config_changes.txt"
            )

        list ( APPEND BUILT_SOURCES config_changes.txt )
    elseif ( RUBY_EXECUTABLE )
        list ( APPEND UNBUILT_SOURCES config_changes.txt )
    endif ( RUBY_EXECUTABLE )

    file ( COPY ${UNBUILT_SOURCES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR} )

    add_custom_target (
        all_doc_sources 
        DEPENDS ${BUILT_SOURCES} ${UNBUILT_SOURCES}
        )

    set ( DOC_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}" )
    set ( SNORT_MANUAL_TXT "${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt" )

    if ( MAKE_HTML_DOC )
        add_subdirectory ( html )
        list ( APPEND BUILT_DIST "${CMAKE_CURRENT_BINARY_DIR}/html/snort_manual.html" )
    endif ( MAKE_HTML_DOC )

    if ( MAKE_TEXT_DOC )
        add_subdirectory ( text )
        list ( APPEND BUILT_DIST "${CMAKE_CURRENT_BINARY_DIR}/text/snort_manual.text" )
    endif ( MAKE_TEXT_DOC )

    if ( MAKE_PDF_DOC )
        add_subdirectory ( pdf )
        list ( APPEND BUILT_DIST "${CMAKE_CURRENT_BINARY_DIR}/pdf/snort_manual.pdf" )
    endif ( MAKE_PDF_DOC )

    foreach ( file_name ${BUILT_SOURCES} )
        list ( APPEND BUILT_DIST "${CMAKE_CURRENT_BINARY_DIR}/${file_name}" )
    endforeach ( file_name )

    if ( BUILT_DIST )
        install ( FILES ${BUILT_DIST} DESTINATION "${SNORT_DATA_DIR}" )
    endif ( BUILT_DIST )

    if ( UNBUILT_SOURCES )
        install ( FILES ${UNBUILT_SOURCES} DESTINATION "${SNORT_DATA_DIR}" )
    endif ( UNBUILT_SOURCES )

    if ( MAKE_HTML_DOC )
        install (
            DIRECTORY
            "${CMAKE_CURRENT_BINARY_DIR}/html/snort_manual.chunked/"
            DESTINATION
            "${SNORT_DATA_DIR}/snort_manual.chunked"
            )

        list ( APPEND EXTRA_CLEAN "${CMAKE_CURRENT_BINARY_DIR}/snort_manual.chunked" )
    endif ( MAKE_HTML_DOC )

    foreach ( file_name ${UNBUILT_SOURCES} )
        list ( APPEND EXTRA_CLEAN "${CMAKE_CURRENT_BINARY_DIR}/${file_name}" )
    endforeach ( file_name )


endif ( MAKE_HTML_DOC OR MAKE_TEXT_DOC OR MAKE_PDF_DOC )

if ( EXTRA_CLEAN )
    set_property (
        DIRECTORY
        PROPERTY
        ADDITIONAL_MAKE_CLEAN_FILES ${EXTRA_CLEAN}
        )
endif ( EXTRA_CLEAN )
