function ( add_help_command generator_script output_file )

    add_custom_command (
        OUTPUT ${output_file}
        COMMAND ${generator_script} $<TARGET_FILE:snort> ${output_file} $ENV{SNORT_PLUGIN_PATH}
        DEPENDS snort
        COMMENT "Documents: building ${output_file} with $ENV{SNORT_PLUGIN_PATH}"
        )

endfunction ( add_help_command )
