

macro (add_compile_flags library flags)


    get_target_property(TEMP ${library} COMPILE_FLAGS)

    if(TEMP STREQUAL "TEMP-NOTFOUND")
        SET(TEMP "") # set to empty string
    else()
        SET(TEMP "${TEMP} ") # a space to cleanly separate from existing content
    endif()

    # append our values
    SET(TEMP "${TEMP} ${flags} " )
    set_target_properties(${library} PROPERTIES COMPILE_FLAGS ${TEMP}) 
endmacro (add_compile_flags)



macro (add_link_flags library)

    get_target_property(TEMP ${library} LINK_FLAGS)

    if(TEMP STREQUAL "TEMP-NOTFOUND")
        SET(TEMP "") # set to empty string
    else()
        SET(TEMP "${TEMP} ") # a space to cleanly separate from existing content
    endif()

    # append our values
    set(TEMP "${TEMP} ${ARGN}" )
    set_target_properties(${library} PROPERTIES LINK_FLAGS "${TEMP}" )

    message(STATUS "setting library -${library} link flags to --> ${TEMP}")
endmacro (add_link_flags)

# TO CALL THIS MACRO...
# PARAMS:
#       libname :  The library's libname
#       additional args : the library's sources.  Must have at least one source
macro (add_shared_library libname install_path)


    set (sources ${ARGN})

    # Did we get any sources?
    list(LENGTH sources num_extra_args)
    if (${num_extra_args} GREATER 0)
        string (REPLACE ";" " " sources "${sources}")

        add_library (${libname} SHARED ${ARGN} )
        set_target_properties ( ${libname} 
            PROPERTIES
            COMPILE_FLAGS "-DBUILDING_SO"
            LINK_FLAGS "-export-dynamic -shared"
        )
        #INSTALL INTO STATIC LIBRARY
        
        install (TARGETS ${libname}
            LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/${install_path}"
        )
    
    else (${num_extra_args} GREATER 0)

        message (STATUS "add_static_library requires at least one source file!")
        message (FATAL "usage: add_static_library lib_name source_1 source_2 source_3 ...")

    endif (${num_extra_args} GREATER 0)
endmacro (add_shared_library)



macro (set_default_visibility_compile_flag libname)
    add_compile_flags(${libname} "-fvisibility=default")
endmacro (set_default_visibility_compile_flag)



macro (add_target_compile_flags library flags)

    get_target_property(TEMP ${library} COMPILE_DEFINITIONS)

    if(TEMP STREQUAL "TEMP-NOTFOUND")
        SET(TEMP "") # set to empty string
    else()
        SET(TEMP "${TEMP} ") # a space to cleanly separate from existing content
    endif()

    # append our values
    SET(TEMP "${TEMP} ${flags} " )
    set_target_properties(${library} PROPERTIES COMPILE_DEFINITIONS ${TEMP}) 
endmacro (add_target_compile_flags)


macro (set_project_compiler_defines_if_true var flag)
    if (${var})
        add_definitions("-D${flag}")
    endif(${var})
endmacro (set_project_compiler_defines_if_true)

macro (set_project_compiler_defines_if_false var flag)
    if (NOT ${var})
        add_definitions("-D${flag}")
    endif()
endmacro (set_project_compiler_defines_if_false)

macro (set_if_true value var)
    if (${value})
        set(${var} "YES")
    endif()
endmacro ()

macro (set_if_false value var)
    if(value)
        set(${var} "NO")
    endif()
endmacro ()

macro (append_to_cache_variable cache_var)

    get_property(cache_value CACHE ${cache_var} PROPERTY VALUE)
    get_property(cache_type CACHE ${cache_var} PROPERTY TYPE)
    get_property(cache_help_string CACHE ${cache_var} PROPERTY HELPSTRING)
    
    set (tmp ${cache_value} ${ARGN})
    set(${cache_var} "${tmp}" CACHE ${cache_type} " ${cache_help_string}")


    message(STATUS ${cache_var} " ${tmp} " CACHE " " ${cache_type} " ${cache_help_string}")
endmacro ()


macro (set_cache_variable cache_var)

    get_property(cache_value CACHE ${cache_var} PROPERTY VALUE)
    get_property(cache_type CACHE ${cache_var} PROPERTY TYPE)
    get_property(cache_help_string CACHE ${cache_var} PROPERTY HELPSTRING)
    
    set (tmp ${cache_value} ${ARGN})
    set(${cache_var} "${tmp}" CACHE ${cache_type} "${cache_help_string}")


    message(STATUS ${cache_var} " ${tmp}" CACHE " " ${cache_type} " ${cache_help_string}")
endmacro ()


