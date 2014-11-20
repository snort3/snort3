## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as
## published by the Free Software Foundation.  You may not use, modify or
## distribute this program under any other version of the GNU General
## Public License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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


        if (${HELP_TYPE} MATCHES "help")
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --help
                OUTPUT_FILE ${OUT_FILE}
            )
        else()
            execute_process (
                COMMAND
                    ${SNORT_EXECUTABLE}
                    ${PLUGIN}
                    --markup
                    --help-${HELP_TYPE}
                COMMAND sort
                OUTPUT_FILE ${OUT_FILE}
            )
        endif()

    elseif (LIST_TYPE)

        execute_process (
            COMMAND
                ${SNORT_EXECUTABLE}
                ${PLUGIN}
                --markup
                --list-${LIST_TYPE}
            COMMAND sort
            OUTPUT_FILE ${OUT_FILE}
        )

    else()
        message (FATAL_ERROR "either MODULE_TYPE, ASCIIDOC_CMD, LIST_TYPE must be defined!")
    endif()


else()
    set (HELP_STR "help")

    if (HELP_STR MATCHES "help")
        message(STATUS "${HELP_STR} MATCHES help")
    else ()
        message(STATUS "${HELP_STR} does NOT match help")
    endif()

    message (FATAL_ERROR "The command \${SNORT_EXECUTABLE} --markup --help-module \${module}"
            " requires a valid options 'SNORT_EXECUTABLE' and 'OUT_FILE'\n"
            " \tSNORT_EXECUTABLE == ${SNORT_EXECUTABLE}\n"
            " \tOUT_FILE == ${OUT_FILE}")
endif()
