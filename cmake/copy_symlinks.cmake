

if (NOT SOURCE_DIRECTORY)
    message (FATAL_ERROR "SOURCE_DIRECTORY must be defined")

else()
    set (link_dir "${SOURCE_DIRECTORY}/tmp")
    execute_process ( COMMAND ${CMAKE_COMMAND} -E make_directory "${link_dir}")


    file (GLOB ALL_FILES RELATIVE ${SOURCE_DIRECTORY} "*")

    foreach (f ${ALL_FILES})
        if ( IS_SYMLINK ${f} )

            #  This two step copy process is necessary to ensure the binary
            #  is copied rather than the symlink.  So, the first 'copy'
            #  command ensure the binary has a newer timestamp than
            #  the symlink (cmake won't copy if the two files have
            #  the same timestamp).  The second copy will overwrite
            #  the original symlink.

            execute_process ( COMMAND ${CMAKE_COMMAND} -E copy "${f}" "${link_dir}/${f}" )
            execute_process ( COMMAND ${CMAKE_COMMAND} -E copy "${link_dir}/${f}" "${f}" )
        endif ( IS_SYMLINK ${f} )
    endforeach(f)

    execute_process ( COMMAND ${CMAKE_COMMAND} -E remove_directory "${link_dir}")
endif()
