
################################################
#  MACRO FOR ADDING EXAMPLE LIBRARIES
#
#  Look in subdirecties for examples. This macro
#  will take care of all the logic, especially adding
#  this to the test configuration
#
#  PARAMS:
#       library ==>  library name to be installed
#       install_path ==> install into folder lib/[snort/snort_ex]/install_path
#       SOURCES ==> all arguments after install path are library sources
#
################################################

macro (add_example_library libname install_path)
    set (sources ${ARGN})

    # Did we get any sources?
    list(LENGTH sources num_extra_args)
    if (${num_extra_args} GREATER 0)

        add_library (${libname} SHARED ${sources} )
        set_target_properties ( ${libname}
            PROPERTIES
            COMPILE_FLAGS "-DBUILDING_SO"
        )

        # If we're testing plugins, set a variable for later use.
        if (BUILD_EXTRA_PLUGINS)
            set (TMP_PLUGINS "${BUILT_PLUGINS}")
            list (APPEND TMP_PLUGINS ${libname})

            # Force implied, but making this explicit
            set (BUILT_PLUGINS "${TMP_PLUGINS}" CACHE INTERNAL "example plugin libraries" FORCE)
        endif (BUILD_EXTRA_PLUGINS)


        install (TARGETS ${libname}
            LIBRARY DESTINATION "${EX_INSTALL_PATH}/${install_path}"
        )

    else (${num_extra_args} GREATER 0)

        message (STATUS "add_static_library requires at least one source file!")
        message (FATAL "usage: add_static_library lib_name source_1 source_2 source_3 ...")

    endif (${num_extra_args} GREATER 0)
endmacro (add_example_library)



################################################
#### SETTING CORRECT VARIABLES FOR BULIDING ####
################################################

if (BUILD_EXTRA_PLUGINS)
    set (TEST_INSTALL_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test_install")
    set (EX_INSTALL_PATH "lib/snort")
    include_directories ("${TEST_INSTALL_DIRECTORY}/include/snort")
    include_directories (${DAQ_INCLUDE_DIR})

    # reset this variable in case Cmake is reconfigured. i.e.,
    # we will keep appending the same libraries multiple times otherwise
    unset (BUILT_PLUGINS CACHE)


else (BUILD_EXTRA_PLUGINS)
    include_directories (${SNORT_INCLUDE_DIR})
    set (EX_INSTALL_PATH "lib/snort_examples")

endif (BUILD_EXTRA_PLUGINS)


################################################
#######  FINALLY, ADDING SUBDIRECTORIES  #######
################################################


add_subdirectory (codecs)
add_subdirectory (inspectors)
add_subdirectory (ips_options)
add_subdirectory (loggers)
add_subdirectory (search_engines)
add_subdirectory (so_rules)


##############################################################################
# When Testing plugins, I want to build snort, install it, and then include
# the installed directory.  This makes sure we install all correct files.
# The result is below.
##############################################################################

if (BUILD_EXTRA_PLUGINS)

    ################################################
    # This variable, DBUILD_EXTRA_PLUGINS, is toggled because
    # when Snort++ builds unit test, this directory will
    # get recursively called from 'make install'. Infinite loops
    # seem like a poor life choice.
    ################################################

    ################################################
    #  Breaking this down by command
    #  1) Remove the previously installed directory (if it exists)
    #       While this may strictly not necessary, this is a
    #       safegaurd to ensure only current files are included.
    #  2) Clean this directory and all subdirectories. This command
    #       works in tandem with WORKING_DIRECTORY to ensure it
    #       only cleans extra plugins.  Also, we check in the top
    #       level cmake file to ensure that Makefiles have been
    #       generated. So, the command is definitely valid.
    #  3) Ensure we don't recursively build this directly. Also,
    #       make sure we install into a temporary directory
    #  4) build snort. Can technically be combined with 'make install'
    #       but lets keep them seperate for clarity.
    #  5) install snort into the temp install directory.
    #  6) reset cmake options
    #  7) Another make is required to ensure the all the configured files
    #       revert to their original form.  I chose u2spewfoo because
    #       it only has one source file
    #  8) possible cmake bug?  timestamp on installed binary not updating.
    #       Manually touch file to ensure we don't needlesly rebuild
    ################################################

    set (TMP_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

    # install Snort into temporary directory
    add_custom_command(
        OUTPUT "${TEST_INSTALL_DIRECTORY}/bin/snort"
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${TEST_INSTALL_DIRECTORY}
        COMMAND make clean
        COMMAND ${CMAKE_COMMAND} ${CMAKE_BINARY_DIR} -DCMAKE_INSTALL_PREFIX=${TEST_INSTALL_DIRECTORY} -DBUILD_EXTRA_PLUGINS=OFF
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target snort
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
        COMMAND ${CMAKE_COMMAND} ${CMAKE_BINARY_DIR} -DCMAKE_INSTALL_PREFIX=${TMP_INSTALL_PREFIX} -DBUILD_EXTRA_PLUGINS=ON
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target u2spewfoo
        COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${TEST_INSTALL_DIRECTORY}/bin/snort
        DEPENDS snort
        COMMENT "Building extra plugins using installed Snort"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_custom_target(install_snort DEPENDS "${TEST_INSTALL_DIRECTORY}/bin/snort")


    #  set in Macro above
    foreach (lib ${BUILT_PLUGINS})
        add_dependencies(${lib} install_snort)
    endforeach(lib)
endif (BUILD_EXTRA_PLUGINS)
