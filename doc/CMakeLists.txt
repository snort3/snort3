
#
# Assuming a file the source file is 'file_name.txt' the BUILT_SOURCES
# files will be created with the following command
#
#  snort --help-file_name > file_name.txt
#
set(BUILT_SOURCES
    builtin.txt
    commands.txt
    config.txt
    options.txt
    gids.txt
#    version.txt   Required special formatting. manually add below.
    CACHE INTERNAL "sources to be built" FORCE
)

set (UNBUILT_SOURCES
    snort_manual.txt
    differences.txt
    style.txt
    tips.txt
    plugins.txt
#    images/snort.png   # images directory is manually included as an a2x option
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
#  BUILT_SOURCES into this directory and create all of the UNBUILT_SOURCES in #
#  this directory.                                                            #
#                                                                             #
#  NOTE: BUILT_SOURCES recipes are actually defined in src/CMakeLists.txt to  #
#  ensure a file dependency on Snort. This section copies those built sources #
#  into this directory.                                                       #
#                                                                             #
###############################################################################

# copy built files into this directory
set (TARGET_DIR ${CMAKE_BINARY_DIR})
foreach (file ${BUILT_SOURCES};version.txt)
    set(input ${CMAKE_BINARY_DIR}/${file})
    set (output ${CMAKE_CURRENT_BINARY_DIR}/${file})

    # create this custom file name so it can be used below. Doesn't actually
    # build the file itself.
    add_custom_command(
        OUTPUT ${input}
        COMMAND ${CMAKE_COMMAND}
            -E touch_nocreate ${input}
    )

    #  complementary section to the foreach loop at the bottom of src/CMakeLists.txt
    add_custom_command(
        OUTPUT ${output}
        COMMAND ${CMAKE_COMMAND}
            -E copy ${input} ${output}
        MAIN_DEPENDENCY ${input}
        COMMENT "Documents: moving ${file} to doc directory"
    )

    get_filename_component(file_name "${file}" NAME_WE)
    add_custom_target(built_doc_${file_name} DEPENDS ${input} ${output})
    add_dependencies(built_doc_${file_name} doc_${file_name})
    
    list(APPEND BUILT_SOURCES_BINARY_PATH ${output})
endforeach(file)


# Copy all distributed files into the binary tree (necessary for asciidocs).
# Then create a dependency between the new and old files.
foreach (file ${UNBUILT_SOURCES})
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file}
        COMMAND ${CMAKE_COMMAND} 
                -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file}
        MAIN_DEPENDENCY ${file}
        COMMENT "Copying ${file} into binary directory"
    )

    list(APPEND UNBUILT_SOURCES_BINARY_PATH "${CMAKE_CURRENT_BINARY_DIR}/${file}")
endforeach(file)

foreach (file ${EXTRA_DIST})
    list(APPEND EXTRA_DIST_BINARY_PATH "${CMAKE_CURRENT_BINARY_DIR}/${file}")
endforeach(file)


set (ALL_SOURCES
    ${BUILT_SOURCES_BINARY_PATH}
    ${UNBUILT_SOURCES_BINARY_PATH}
)


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
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/snort_manual.txt
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
    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/snort_manual.txt
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
add_dependencies(snort_manuals snort ${ALL_SOURCES})



install (FILES ${EXTRA_DIST_BINARY_PATH}
    DESTINATION "doc"
)

