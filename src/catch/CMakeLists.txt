
if ( ENABLE_UNIT_TESTS )

add_library(catch_tests STATIC
    catch.hpp
    unit_test.cc
    unit_test.h
)

target_link_libraries(catch_tests)

endif()
