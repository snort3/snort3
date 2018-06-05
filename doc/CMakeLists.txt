if ( MAKE_DOC )
    add_custom_target ( snort_manuals ALL )

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
	connector.txt
	data.txt
	inspector.txt
	ips_action.txt
	ips_option.txt
	logger.txt
    )

    set (
	UNBUILT_SOURCES
	active.txt
	appid.txt
	binder.txt
	building.txt
	byte_extract.txt
	byte_jump.txt
	byte_math.txt
	byte_test.txt
	concepts.txt
	connectors.txt
	daq.txt
	daq_readme.txt
	dcerpc.txt
	differences.txt
	enviro.txt
	errors.txt
	extending.txt
	features.txt
	file_processing.txt
	ftp.txt
	high_availability.txt
	http_inspect.txt
	http2_inspect.txt
	module_trace.txt
	overview.txt
	params.txt
	perf_monitor.txt
	pop_imap.txt
	reference.txt
	sensitive_data.txt
	port_scan.txt
	side_channel.txt
	smtp.txt
	snort2lua.txt
	snort2x.png
	snort3x.png
	snort_manual.html
	snort_manual.pdf
	snort_manual.text
	snort_manual.txt
	snorty.png
	style.txt
	telnet.txt
	terms.txt
	testing_numerical_values.txt
	tutorial.txt
	usage.txt
	wizard.txt
    )

    function ( add_help_command generator_script output_file )
	add_custom_command (
	    OUTPUT ${output_file}
	    COMMAND ${generator_script} $<TARGET_FILE:snort> ${output_file} $ENV{SNORT_PLUGIN_PATH}
	    DEPENDS snort
	    COMMENT "Documents: building ${output_file} with $ENV{SNORT_PLUGIN_PATH}"
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

    set ( BUILT_DIST ${BINARY_DIR_BUILT_SOURCES} ${BINARY_DIR_UNBUILT_SOURCES} )

    add_custom_target (
	all_built_sources
	DEPENDS ${BUILT_SOURCES}
    )

    add_dependencies ( snort_manuals all_built_sources )

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

	add_custom_command (
	    OUTPUT snort_manual.html
	    COMMAND cp ${LIST_DIR_SOURCES} .
	    COMMAND ${ASCIIDOC_EXE} ${HTML_ASCIIDOC_ARGS} snort_manual.txt
	    DEPENDS all_built_sources
	    COMMENT "Documents: building snort_manual.html"
	)

	set ( HTML_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/html/" )

	add_custom_command (
	    OUTPUT "${HTML_DOC_TMP}/"
	    COMMAND mkdir -p ${HTML_DOC_TMP}
	)

	add_custom_command (
	    OUTPUT snort_manual.tgz
	    COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
	    COMMAND ${ASCIIDOC_A2X_EXE} ${HTML_A2X_ARGS} snort_manual.txt
	    COMMAND cp -r snort_manual.chunked ..
	    COMMAND tar zcf ../snort_manual.tgz -C ../ snort_manual.chunked
	    DEPENDS all_built_sources "${HTML_DOC_TMP}/"
	    WORKING_DIRECTORY ${HTML_DOC_TMP}
	    COMMENT "Documents: building snort_manual.tgz"
	)

	add_custom_target (
	    html
	    COMMAND rm -rf ${HTML_DOC_TMP}
	    DEPENDS snort_manual.html snort_manual.tgz
	)

	foreach ( file_name ${UNBUILT_SOURCES} )
	    list (
		APPEND
		BINARY_DIR_UNBUILT_SOURCES
		"${CMAKE_CURRENT_BINARY_DIR}/${file_name}"
	    )
	endforeach ( file_name )

	list (
	    APPEND
	    EXTRA_CLEAN
	    "${CMAKE_CURRENT_BINARY_DIR}/snort_manual.chunked"
	    "${CMAKE_CURRENT_BINARY_DIR}/snort_manual.tgz"
	)

	add_custom_target (
	    snort_online.html
	    COMMAND ${CMAKE_SOURCE_DIR}/doc/online_manual.sh
	    DEPENDS all_built_sources
	)

	add_custom_target (
	    dev_guide.html
	    COMMAND ${CMAKE_SOURCE_DIR}/doc/dev_guide.sh ${CMAKE_SOURCE_DIR}
	    DEPENDS all_built_sources
	)
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
	    OUTPUT snort_manual.text
	    COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
	    COMMAND ${ASCIIDOC_A2X_EXE} ${TEXT_A2X_ARGS} snort_manual.txt
	    COMMAND cp snort_manual.text ..
	    DEPENDS all_built_sources "${TEXT_DOC_TMP}/"
	    WORKING_DIRECTORY ${TEXT_DOC_TMP}
	    COMMENT "Documents: building snort_manual.text"
	)

	add_custom_target (
	    text
	    COMMAND rm -rf ${TEXT_DOC_TMP}
	    DEPENDS snort_manual.text
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
	    OUTPUT snort_manual.pdf
	    COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} .
	    COMMAND ${ASCIIDOC_A2X_EXE} ${PDF_A2X_ARGS} snort_manual.txt
	    COMMAND cp snort_manual.pdf ..
	    DEPENDS all_built_sources "${PDF_DOC_TMP}/"
	    WORKING_DIRECTORY ${PDF_DOC_TMP}
	    COMMENT "Documents: building snort_manual.pdf"
	)

	add_custom_target (
	    pdf
	    COMMAND rm -rf ${PDF_DOC_TMP}
	    DEPENDS snort_manual.pdf
	)
    endif ( MAKE_PDF_DOC )

    install (
	FILES
	${BUILT_DIST}
	${UNBUILT_SOURCES}
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

endif ( MAKE_DOC )
