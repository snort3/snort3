

# List all Flex and bison sources here.  This file will automatically compile
# and add these sources to the target_based library dependancies list.
set ( BISON_SRC sf_attribute_table.y)
set ( FLEX_SRC )


# Build the header file.  Custom command due to extra mv command
add_custom_command ( 
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sf_attribute_table.h  
    COMMAND ${BISON_EXECUTABLE} -y -d -psfat_ 
            ${CMAKE_CURRENT_SOURCE_DIR}/sf_attribute_table.y
    COMMAND mv y.tab.h sf_attribute_table.h  
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/sf_attribute_table.y
    COMMENT "Bison: Bison generating sf_atttribute_table.h"
)
set(generated_files ${generated_files} ${CMAKE_CURRENT_BINARY_DIR}/sf_attribute_table.h )


# this is a custom command due to the extra dependency.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sf_attribute_table_parser.c
    COMMAND ${FLEX_EXECUTABLE} 
        -i -Psfat 
        -o ${CMAKE_CURRENT_BINARY_DIR}/sf_attribute_table_parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/sf_attribute_table_parser.l
    MAIN_DEPENDENCY sf_attribute_table_parser.l
    DEPENDS sf_attribute_table.h
    VERBATIM
    COMMENT "Flex: generating sf_attribute_table_parser.c"
)
set(generated_files ${generated_files} ${CMAKE_CURRENT_BINARY_DIR}/sf_attribute_table_parser.c )



# Generate all source fiels using Bison
foreach (file ${BISON_SRC})
    
    if (NOT IS_ABSOLUTE "${file}")
        set(file "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
    endif()

    get_filename_component(file_name "${file}" NAME_WE)
    set (output_file "${CMAKE_CURRENT_BINARY_DIR}/${file_name}.c")
    set (generated_files ${generated_files} ${output_file} )

    add_custom_command ( 
        OUTPUT ${output_file} 
        COMMAND ${BISON_EXECUTABLE}
            -y -d -psfat_
            -o "${output_file}"
            "${file}"
        DEPENDS "${file}"
        COMMENT "BISON: generating ${file_name}.c from ${file}"
    )
endforeach(file)


# Generate all source files using Flex
foreach (file ${FLEX_SRC})
    if (NOT IS_ABSOLUTE "${file}")
        set(file "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
    endif()
    get_filename_component(file_name "${file}" NAME_WE)
    set (output_file "${CMAKE_CURRENT_BINARY_DIR}/${file_name}.c")
    set(generated_files ${generated_files} ${output_file} )

    add_custom_command ( 
        OUTPUT ${output_file} 
        COMMAND ${FLEX_EXECUTABLE} -i
            -o "${output_file}"
            "${file}"
        DEPENDS "${file}"
        COMMENT "FLEX: generating ${file_name}.c from ${file}"
    )
endforeach(file)



add_library( target_based STATIC
    sftarget_reader.cc 
    sftarget_reader.h
    sftarget_hostentry.cc
    sftarget_hostentry.h
    sftarget_data.h
    sftarget_protocol_reference.cc
    sftarget_protocol_reference.h
    sf_attribute_table_parser.c
    sf_attribute_table.y
    ${generated_files}
)

