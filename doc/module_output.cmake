

if (SNORT_EXECUTABLE AND OUT_FILE)

    # clear any previous data in the file
    execute_process (
        COMMAND ${CMAKE_COMMAND} -E echo ""
        OUTPUT_FILE ${OUT_FILE}
    )

    #  get the list of modules from Snort
    execute_process (
        COMMAND ${SNORT_EXECUTABLE} --list-modules
        OUTPUT_FILE ${OUT_FILE}.list
    )

    file (STRINGS "${OUT_FILE}.list" MODULES)
    file (REMOVE "${OUT_FILE}.list")


    foreach (m ${MODULES})
        execute_process (
            COMMAND ${SNORT_EXECUTABLE} --markup --help-module ${m}
            OUTPUT_VARIABLE CONTENTS
        )

        file (APPEND ${OUT_FILE} "${CONTENTS}")
    endforeach(m ${MODULES})

else ()
    message (FATAL_ERROR "The options 'SNORT_EXECUTABLE' and 'OUT_FILE' must be provided to this script!!!")

endif()

