
if (SNORT_EXECUTABLE AND OUT_FILE)

    # unsure why the extra level of indirection is needed, but it is
    set (PLUG_PATH $ENV{SNORT_PLUGIN_PATH})
    if (PLUG_PATH)
        set (PLUGIN "--plugin-path=$ENV{SNORT_PLUGIN_PATH}")
    endif ()


    if (MODULE_TYPE)

        # clear any previous data in the file
        execute_process (
            COMMAND ${CMAKE_COMMAND} -E echo ""
            OUTPUT_FILE ${OUT_FILE}
        )

        #  get the list of modules from Snort
        execute_process (
            COMMAND ${SNORT_EXECUTABLE} --list-modules ${MODULE_TYPE}
            OUTPUT_FILE ${OUT_FILE}.list
        )

        file (STRINGS "${OUT_FILE}.list" MODULE_TYPE)
        file (REMOVE "${OUT_FILE}.list")


        foreach (m ${MODULE_TYPE})
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --help-module
                    ${m}
                OUTPUT_VARIABLE CONTENTS
            )

            file (APPEND ${OUT_FILE} "${CONTENTS}")
        endforeach(m ${MODULE_TYPE})

    elseif (HELP_TYPE)


        if (HELP_TYPE MATCHES "help")
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --help
                OUTPUT_FILE ${OUT_FILE}
            )
        else()
            if (${HELP_TYPE} STREQUAL "config")
                set (SORT_OPTIONS "-k 3")
            elseif (${HELP_TYPE} STREQUAL "counts")
                set (SORT_OPTIONS "-k 2")
            endif(${HELP_TYPE} STREQUAL "config")


            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --help-${HELP_TYPE}
                COMMAND sort ${SORT_OPTIONS}
                OUTPUT_FILE ${OUT_FILE}
            )
        endif()

    elseif (LIST_TYPE)
        if (LIST_TYPE STREQUAL "gids")
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --list-${LIST_TYPE}
                COMMAND sort -n -k 1.4
                OUTPUT_FILE ${OUT_FILE}
            )
        elseif (${LIST_TYPE} STREQUAL "builtin")
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --list-${LIST_TYPE}
                COMMAND sort -n -t : -k 1.4 -k 2
                OUTPUT_FILE ${OUT_FILE}
            )
        else()
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --list-${LIST_TYPE}
                COMMAND sort ${SORT_OPTIONS}
                OUTPUT_FILE ${OUT_FILE}
            )

        endif(LIST_TYPE STREQUAL "gids")

    else()
        message (FATAL_ERROR "either MODULE_TYPE, HELP_TYPE, LIST_TYPE must be defined!")
    endif()


else()
    message (FATAL_ERROR "This script requires valid 'SNORT_EXECUTABLE' and\n"
            "'OUT_FILE' variables.  Run this script with the command"
            "    cmake -DSNORT_EXECUTABLE=/path/to/snort -DOUT_FILE=/path/to/outfile"
            "        -P ${CMAKE_CURRENT_LIST_FILE}"
            )
endif()
