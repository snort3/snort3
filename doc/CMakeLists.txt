

##############################################################################
#                                                                            #
#  To build another .txt file, add the file to the BUILT_SOURCES variable.   #
#  If the new file's name is new_file.txt, Cmake will automatcially run the  #
#  command                                                                   #
#                                                                            #
#  >>  snort --help-file_name > file_name.txt                                #
#                                                                            #
#  to creat the new file. Notice that the extension is missing in the help   #
#  command. If the command does not exist, the behavior is undefined althogh #
#  an error will definitely occur.                                           #
#                                                                            #
##############################################################################

# snort --help-${type}
set(HELP_SOURCES
    commands.txt
    config.txt
    modules.txt
    plugins.txt
    options.txt
    signals.txt
    help.txt
#   snort2lua_cmds.txt   Get Snort2Lua command line options
)

# snort --list-${type}
set(LIST_SOURCES
    builtin.txt
    gids.txt
)

# snort --help-module ${module}
set (MODULE_SOURCES
    basic.txt
    codec.txt
    data.txt
    inspector.txt
    ips_action.txt
    ips_option.txt
    logger.txt
)

set(BUILT_SOURCES
    ${HELP_SOURCES}
    ${LIST_SOURCES}
    ${MODULE_SOURCES}
#   version.txt         Requires special formatting. manually added below.
#   config_changes.txt  If ruby executable found
)

set (UNBUILT_SOURCES
    snort_manual.txt
    overview.txt
    errors.txt
    enviro.txt
    features.txt
    differences.txt
    extending.txt
    params.txt
    reference.txt
    snort2lua.txt
    start.txt
    style.txt
    terms.txt
#   config_changes.txt  If ruby executable is NOT found
)


if (MAKE_HTML_DOC)
    set(HTML_DOCS
        snort_manual.html
        snort_manual.tgz
        images.tgz
    )
endif()

if (MAKE_PDF_DOC)
    set(PDF_DOCS snort_manual.pdf)
endif()

# Docuements to be built
set (EXTRA_DIST ${HTML_DOCS} ${PDF_DOCS})


###############################################################################
###############################################################################


###############################################################################
#                                                                             #
#  Since we'd lke to keep the source tree unpolluted, create all targets in   #
#  the build directory.  This section adds custom commands to copy all of the #
#  UNBUILT_SOURCES into this directory and create all of the BUILT_SOURCES in #
#  this directory.                                                            #
#                                                                             #
#                                                                             #
###############################################################################


if (MAKE_PDF_DOC OR MAKE_HTML_DOC)

    # first, build all of the documents in the binary tree

    foreach (file ${HELP_SOURCES})
        set (output "${CMAKE_CURRENT_BINARY_DIR}/${file}")
        get_filename_component(file_name "${file}" NAME_WE)

        add_custom_command(
            OUTPUT ${output}
            COMMAND ${CMAKE_COMMAND}
                -DOUT_FILE=${output}
                -DSNORT_EXECUTABLE=$<TARGET_FILE:snort>
                -DHELP_TYPE=${file_name}
                -P ${CMAKE_CURRENT_LIST_DIR}/cmake_scripts.cmake
            DEPENDS snort cmake_scripts.cmake
            COMMENT "Documents: building ${file}"
        )
        list(APPEND ALL_SOURCES ${output})
    endforeach(file)

    foreach (file ${LIST_SOURCES})
        set (output "${CMAKE_CURRENT_BINARY_DIR}/${file}")
        get_filename_component(file_name "${file}" NAME_WE)

        add_custom_command(
            OUTPUT ${output}
            COMMAND ${CMAKE_COMMAND}
                -DOUT_FILE=${output}
                -DSNORT_EXECUTABLE=$<TARGET_FILE:snort>
                -DLIST_TYPE=${file_name}
                -P ${CMAKE_CURRENT_LIST_DIR}/cmake_scripts.cmake
            DEPENDS snort cmake_scripts.cmake
            COMMENT "Documents: building ${file}"
        )
        list(APPEND ALL_SOURCES ${output})
    endforeach(file)

    foreach (module ${MODULE_SOURCES})
        set (output "${CMAKE_CURRENT_BINARY_DIR}/${module}")
        get_filename_component(module_name "${module}" NAME_WE)

        add_custom_command(
            OUTPUT ${output}
            COMMAND ${CMAKE_COMMAND}
                -DOUT_FILE=${output}
                -DSNORT_EXECUTABLE=$<TARGET_FILE:snort>
                -DMODULE_TYPE=${module_name}
                -P ${CMAKE_CURRENT_LIST_DIR}/cmake_scripts.cmake
            DEPENDS snort cmake_scripts.cmake
            COMMENT "Documents: building ${module}"
        )
        list(APPEND ALL_SOURCES ${output})
    endforeach(module)

    # build version.txt seperately
    set (output ${CMAKE_CURRENT_BINARY_DIR}/version.txt)
    add_custom_command(
        OUTPUT ${output}
        COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -v Using > ${output}
        DEPENDS snort
        COMMENT "Documents: building version.txt"
    )
    list(APPEND ALL_SOURCES ${output})

    # If ruby is present, built the configuration differences
    if (RUBY_EXECUTABLE)
        set (input ${CMAKE_CURRENT_LIST_DIR}/config_changes.txt)
        set (output ${CMAKE_CURRENT_BINARY_DIR}/config_changes.txt)
        add_custom_command(
            OUTPUT ${output}
            COMMAND ${RUBY_EXECUTABLE}
                ${CMAKE_CURRENT_LIST_DIR}/get_differences.rb
                ${CMAKE_SOURCE_DIR}/tools/snort2lua
                > ${input}
            COMMAND ${CMAKE_COMMAND} -E copy ${input} ${output}
            DEPENDS snort2lua ${CMAKE_CURRENT_LIST_DIR}/get_differences.rb
            COMMENT "Documents: building config_changes.txt"
        )
        list (APPEND ALL_SOURCES ${output})
    else()
        list (APPEND UNBUILT_SOURCES conf_differences.txt)
    endif()

    # next, Copy all distributed files into the binary tree (necessary for asciidocs).
    # Then create a dependency between the new and old files.
    foreach (file ${UNBUILT_SOURCES})
        set (input  "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
        set (output "${CMAKE_CURRENT_BINARY_DIR}/${file}")
        add_custom_command(
            OUTPUT ${output}
            COMMAND ${CMAKE_COMMAND} -E copy ${input} ${output}
            DEPENDS ${input}
            COMMENT "Copying ${file} into binary directory"
        )

        list(APPEND ALL_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/${file}")
    endforeach(file)

    foreach (file ${EXTRA_DIST})
        list(APPEND EXTRA_DIST_BINARY_PATH "${CMAKE_CURRENT_BINARY_DIR}/${file}")
    endforeach(file)

endif()

###############################################################################
###############################################################################

#  create the recipes for building the files


set (PDF_ARGUMENTS --icons --icons-dir=./images/icons --resource=${CMAKE_CURRENT_SOURCE_DIR}/images )
set (HTML_ARGUMENTS --copy --attribute linkcss --attribute stylesdir --attribute disable-javascript --attribute quirks! ${PDF_ARGUMENTS})

add_custom_command(OUTPUT snort_manual.html
    COMMAND ${ASCIIDOC_EXE}
        -b xhtml11
        -a toc2
        -a icons
        -a imagesdir=${CMAKE_CURRENT_SOURCE_DIR}/images
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt 
    DEPENDS ${ALL_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Documents: building snort_manual.html"
)

add_custom_command(OUTPUT snort_manual.pdf
    COMMAND ${ASCIIDOC_A2X_EXE}  
        -f pdf 
        ${PDF_ARGUMENTS} 
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt 
    DEPENDS  ${ALL_SOURCES}
    COMMENT "Documents: building snort_manual.pdf"
)

add_custom_command(OUTPUT snort_manual.tgz
    COMMAND ${ASCIIDOC_A2X_EXE} 
        -f chunked 
        ${HTML_ARGUMENTS} 
        --resource=${CMAKE_CURRENT_BINARY_DIR} 
        --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt 
    COMMAND ${CMAKE_COMMAND} 
        -E tar 
        zcf snort_manual.tgz
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.chunked
    DEPENDS ${ALL_SOURCES} snort_manual.html
    COMMENT "Documents: building snort_manual.tgz"
)

add_custom_command(OUTPUT images.tgz
    COMMAND
        ${CMAKE_COMMAND}
        -E tar zcf ${CMAKE_CURRENT_BINARY_DIR}/images.tgz .
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/images ${ALL_SOURCES}
    COMMENT "Documents: building images.tgz"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/images
)


###############################################################################
###############################################################################

# Finally, the commands to set the manual dependencies and install the
# built documents


add_custom_target(snort_manuals ALL
    DEPENDS ${EXTRA_DIST}
)
#add_dependencies(snort_manuals snort ${ALL_SOURCES})



install (FILES ${EXTRA_DIST_BINARY_PATH}
    DESTINATION "doc"
)
