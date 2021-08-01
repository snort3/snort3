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
            DESTINATION "${PLUGIN_INSTALL_PATH}/${install_path}"
    )
endmacro (add_dynamic_module)

macro (add_dynamic_daq_module libname )
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
            DESTINATION "${LIB_INSTALL_PATH}/daq"
    )
endmacro (add_dynamic_daq_module)


function (add_cpputest testname)
    if ( ENABLE_UNIT_TESTS )
        set(multiValueArgs SOURCES LIBS)
        cmake_parse_arguments(CppUTest "" "" "${multiValueArgs}" ${ARGN})
        add_executable(${testname} EXCLUDE_FROM_ALL ${testname}.cc ${CppUTest_SOURCES})
        target_compile_options(${testname} PRIVATE "-DUNIT_TEST_BUILD")
        target_include_directories(${testname} PRIVATE ${CPPUTEST_INCLUDE_DIR})
        target_link_libraries(${testname} ${CPPUTEST_LIBRARIES} ${CppUTest_LIBS})
        add_test(${testname} ${testname})
        add_dependencies(check ${testname})
    endif ( ENABLE_UNIT_TESTS )
endfunction (add_cpputest)


function (add_catch_test testname)
    if ( ENABLE_UNIT_TESTS )
        set(options NO_TEST_SOURCE)
        set(multiValueArgs SOURCES LIBS)
        cmake_parse_arguments(Catch "${options}" "" "${multiValueArgs}" ${ARGN})
        if ( NOT Catch_NO_TEST_SOURCE )
            set(Test_SOURCE ${testname}.cc)
        endif()
        add_executable(${testname}
            EXCLUDE_FROM_ALL
            ${Test_SOURCE}
            ${Catch_SOURCES}
            $<TARGET_OBJECTS:catch_main>
        )
        target_compile_options(${testname} PRIVATE "-DCATCH_TEST_BUILD")
        target_link_libraries(${testname} PRIVATE ${Catch_LIBS})
        add_test(${testname} ${testname})
        add_dependencies(check ${testname})
    endif ( ENABLE_UNIT_TESTS )
endfunction (add_catch_test)
