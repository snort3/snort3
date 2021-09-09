
if ( ENABLE_UNIT_TESTS OR ENABLE_BENCHMARK_TESTS )

    set (CATCH_INCLUDES
        catch.hpp
        snort_catch.h
    )

    install (FILES ${CATCH_INCLUDES}
        DESTINATION "${INCLUDE_INSTALL_PATH}/catch"
    )

    add_library(catch_tests OBJECT
        ${CATCH_INCLUDES}
        unit_test.cc
        unit_test.h
    )

    add_library(catch_main OBJECT
        EXCLUDE_FROM_ALL
        catch_main.cc
    )

endif( ENABLE_UNIT_TESTS OR ENABLE_BENCHMARK_TESTS )
