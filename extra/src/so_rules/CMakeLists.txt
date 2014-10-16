
# Use this macro to create text files
macro (create_txt_header txt_file hdr_file)

    add_custom_command( OUTPUT ${hdr_file}
        COMMAND
            "${SNORT_EXECUTABLE}" --rule-to-text < "${CMAKE_CURRENT_SOURCE_DIR}/${txt_file}" > "${CMAKE_CURRENT_BINARY_DIR}/${hdr_file}"
        DEPENDS "${txt_file}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "so_rules: Building ${hdr_file}"
    )
    include_directories(${CMAKE_CURRENT_BINARY_DIR})

endmacro (create_txt_header)

# Use this macro to create hex files
macro (create_pro_header txt_file hdr_file)

    add_custom_command( OUTPUT ${hdr_file}
        COMMAND
            "${SNORT_EXECUTABLE}" --rule-to-hex < "${CMAKE_CURRENT_SOURCE_DIR}/${txt_file}" > "${CMAKE_CURRENT_BINARY_DIR}/${hdr_file}"
        DEPENDS "${txt_file}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "so_rules: Building ${hdr_file}"
    )
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
endmacro (create_txt_header)


create_txt_header(sid_18758.txt sid_18758.h)
add_example_library(18758 so_rules sid_18758.cc sid_18758.h)


# if we had a .pro file name 187589.pro and a source file names sid_18759.cc
#create_txt_header(187589.pro 187589.h)
#add_example_library(187589 so_rules 187589.cc 187589.h)
