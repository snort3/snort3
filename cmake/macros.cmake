# TO CALL THIS MACRO...
# PARAMS:
#       libname :  The library's libname
#       additional args : the library's sources.  Must have at least one source
macro (add_shared_library libname install_path)
    set (sources ${ARGN})

    add_library ( ${libname} SHARED ${sources} )
    set_target_properties (
        ${libname}
        PROPERTIES
            COMPILE_FLAGS "-DBUILDING_SO"
    )

    install (
        TARGETS ${libname}
        LIBRARY
            DESTINATION "lib/${CMAKE_PROJECT_NAME}/${install_path}"
    )
endmacro (add_shared_library)


#anything following testname is assumed to be a link dependency
macro (add_cpputest testname)
    if ( ENABLE_UNIT_TESTS )
        add_executable (${testname} EXCLUDE_FROM_ALL ${testname}.cc)
        target_include_directories (${testname} PRIVATE ${CPPUTEST_INCLUDE_DIRS})
        target_link_libraries (${testname} ${CPPUTEST_LIBRARIES} ${ARGN})
        add_test (${testname} ${testname})
        add_dependencies ( check ${testname} )
    endif ( ENABLE_UNIT_TESTS )
endmacro (add_cpputest)
