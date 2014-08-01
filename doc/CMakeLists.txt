

##############################################################################
#                                                                            #
#  To build another .txt file, add the file to the BUILT_SOURCES variable.   #
#  If the new file's name is new_file.txt, cmake will automatcially run the  #
#  command                                                                   #
#                                                                            #
#  >>  snort --help-file_name > file_name.txt                                #
#                                                                            #
#  to creat the new file. Notice that the extension is missing in the help   #
#  command. If the command does not exist, the behavior is undefined althogh #
#  an error will definitely occur.                                           #
#                                                                            #
##############################################################################

set(BUILT_SOURCES
    builtin.txt
    commands.txt
    config.txt
    options.txt
    gids.txt
#   modules.txt         Requires Special formatting. manually added below.
#   version.txt         Required special formatting. manually added below.
#   config_changes.txt  If ruby executable found
    CACHE INTERNAL "sources to be built" FORCE
)

set (UNBUILT_SOURCES
    snort_manual.txt
    differences.txt
    style.txt
    tips.txt
    plugins.txt
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

    foreach (file ${BUILT_SOURCES})
        set (output "${CMAKE_CURRENT_BINARY_DIR}/${file}")
        get_filename_component(file_name "${file}" NAME_WE)

        add_custom_command(
            OUTPUT ${output}
            COMMAND $<TARGET_FILE:snort> --markup --help-${file_name} | sort > ${output}
            DEPENDS snort
            COMMENT "Documents: building ${file}"
        )
        list(APPEND ALL_SOURCES ${output})
    endforeach(file)

    # build version.txt seperately
    set (output ${CMAKE_CURRENT_BINARY_DIR}/version.txt)
    add_custom_command(
        OUTPUT ${output}
        COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -v Using > ${output}
        DEPENDS snort
        COMMENT "Documents: building version.txt"
    )
    list(APPEND ALL_SOURCES ${output})

    # build modules.txt seperately
    set (output ${CMAKE_CURRENT_BINARY_DIR}/modules.txt)
    add_custom_command(
        OUTPUT ${output}
        COMMAND ${CMAKE_COMMAND}
            -DOUT_FILE=${output}
            -DSNORT_EXECUTABLE=$<TARGET_FILE:snort>
            -P ${CMAKE_CURRENT_LIST_DIR}/module_output.cmake
        DEPENDS snort ${CMAKE_CURRENT_LIST_DIR}/module_output.cmake
        COMMENT "Documents: building modules.txt"
    )
    list (APPEND ALL_SOURCES ${output})


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
            DEPENDS snort2lua
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
    COMMAND ${ASCIIDOC_A2X_EXE} 
        -f xhtml 
        ${HTML_ARGUMENTS} 
        --resource=${CMAKE_CURRENT_BINARY_DIR}
        --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt 
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/snort_manual.txt ${ALL_SOURCES}
    COMMENT "Documents: building snort_manual.html"
)

add_custom_command(OUTPUT snort_manual.pdf
    COMMAND ${ASCIIDOC_A2X_EXE}  
        -f pdf 
        ${PDF_ARGUMENTS} 
        ${CMAKE_CURRENT_BINARY_DIR}/snort_manual.txt 
    DEPENDS  ${ALL_SOURCES} snort_manual.html
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
    DEPENDS ${ALL_SOURCES}
    COMMENT "Documents: building snort_manual.tgz"
)

add_custom_command(OUTPUT images.tgz
    COMMAND tar 
        zcf images.tgz 
        --exclude callouts 
        --exclude README
        -C ${CMAKE_CURRENT_SOURCE_DIR}/images
        .
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/images ${ALL_SOURCES}
    COMMENT "Documents: building images.tgz"
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
