
#
# This list of built sources MUST be kept up to date with
# the actual build targets located at the bottom of src/CMakelists.txt
#
set(BUILT_SOURCES
    builtin.txt
    commands.txt
    config.txt
    options.txt
    gids.txt
)

set (UNBUILT_SOURCES
    snort_manual.txt
    differences.txt
    style.txt
    tips.txt
    images/snort.png
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
###############################################################################


###############################################################################
#                                                                             #
#  Since we'd lke to keep the source tree unpolluted, only build targets      #
#  in the build directory.  The rest of this file creates custom commands to  #
#  copy all of the documents into the doc/ directory.                         #
#                                                                             #
###############################################################################


#  Due to the depency on the snort executable, the files are created in a 
#  different directory and copied into the top level of the build directory
#  This next loop copies all of the appropriate files into the doc direcotry

set (TARGET_DIR ${CMAKE_BINARY_DIR})
foreach (file ${BUILT_SOURCES})
    set(input ${CMAKE_BINARY_DIR}/${file})
    set (output ${CMAKE_CURRENT_BINARY_DIR}/${file})

    add_custom_command(
        OUTPUT ${input}
        COMMAND ${CMAKE_COMMAND}
            -E touch_nocreate ${input}
    )

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


#copying the images directory!
add_custom_target(copy_images DEPENDS images)
add_custom_command(
    OUTPUT images
    COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/images ${CMAKE_CURRENT_BINARY_DIR}/images
    COMMENT "Copying doc/images.  If the doc/images directory changes, rerun the cmake command!!"
)
set_source_files_properties(images SYMBOLIC "YES")


# Copy all distributed files into the binary tree (necessary for asciidocs).
# Then create a dependency between the new and old files.
foreach (file ${UNBUILT_SOURCES})
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file}
        COMMAND ${CMAKE_COMMAND} 
                -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file}
        MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/${file}
        DEPENDS copy_images
        COMMENT "Copying ${file} into binary directory"
    )

    list(APPEND UNBUILT_SOURCES_BINARY_PATH "${CMAKE_CURRENT_BINARY_DIR}/${file}")
#    set(UNBUILT_SOURCES_BINARY_PATH "${UNBUILT_SOURCES_BINARY_PATH} ${CMAKE_CURRENT_BINARY_DIR}/${file}")
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

#  This part contains all of the custom commmands for creating the actual
#  documentation.


set (PDF_ARGUMENTS --icons --icons-dir=./images/icons -a imagesdir=./images)
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
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/images ${ALL_SOURCES}
    COMMENT "Documents: building snort_manual.tgz"
)

add_custom_command(OUTPUT images.tgz
    COMMAND tar 
        zcf images.tgz 
        --exclude callouts 
        --exclude README
        -C ${CMAKE_CURRENT_BINARY_DIR}/images 
        .
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/images ${ALL_SOURCES}
    COMMENT "Documents: building images.tgz"
)


###############################################################################
###############################################################################

# Finally, the commands to create the manuals, and the command to install the 
# manuals


add_custom_target(snort_manuals ALL
    DEPENDS ${EXTRA_DIST}
)
add_dependencies(snort_manuals snort)



install (FILES ${EXTRA_DIST_BINARY_PATH}
    DESTINATION "doc"
)

