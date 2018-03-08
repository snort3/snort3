
if ( ENABLE_UNIT_TESTS )

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

endif()
