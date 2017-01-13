# TO CALL THIS MACRO...
# PARAMS:
#       libname :  The module's name
#       additional args : the module's sources.  Must have at least one source
macro (add_dynamic_module libname install_path)
    set (sources ${ARGN})

    add_library ( ${libname} MODULE ${sources} )
    set_target_properties (
        ${libname}
        PROPERTIES
            COMPILE_FLAGS "-DBUILDING_SO"
            PREFIX ""
    )

    if (APPLE)
        set_target_properties (
            ${libname}
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
        )
    endif()

    install (
        TARGETS ${libname}
        LIBRARY
            DESTINATION "lib/${CMAKE_PROJECT_NAME}/${install_path}"
    )
endmacro (add_dynamic_module)


#anything following testname is assumed to be a link dependency
macro (add_cpputest testname)
    if ( ENABLE_UNIT_TESTS )
        add_executable (${testname} EXCLUDE_FROM_ALL ${testname}.cc)
        target_include_directories (${testname} PRIVATE ${CPPUTEST_INCLUDE_DIR})
        target_link_libraries (${testname} ${CPPUTEST_LIBRARIES} ${ARGN})
        add_test (${testname} ${testname})
        add_dependencies ( check ${testname} )
    endif ( ENABLE_UNIT_TESTS )
endmacro (add_cpputest)
