
if ( BUILD_UNIT_TESTS )

find_package(CHECK REQUIRED)
include_directories(AFTER ${CHECK_INCLUDE_DIR})

if ( LINUX )
    find_library(LIBRT rt)

    if ( NOT LIBRT )
        message(SEND_ERROR "librt required.")
    endif()
endif()

# FIXIT-L why do these custom commands always run?
add_custom_command(
    OUTPUT suite_decl.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_decl.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS build_decl.sh
)

add_custom_command(
    OUTPUT suite_list.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_list.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS build_list.sh
)

add_library(catch_tests STATIC
    catch.hpp
    unit_test.cc
    unit_test.h
)

target_link_libraries(catch_tests
    ${CHECK_LIBRARIES}
    ${LIBRT}
)

endif()
