
if ( BUILD_UNIT_TESTS )

find_package(CHECK REQUIRED)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})  # for generated files
include_directories(AFTER ${CHECK_INCLUDE_DIR})

if ( LINUX )
    find_library(LIBRT rt)

    if ( NOT LIBRT )
        message(FATAL_ERROR "librt required. Specicy it by user ")
    endif()
endif()

#  Generating build_decl.h  Will rebuild every time 'make' is run
add_custom_target(build_suit_decl ALL
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_list.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "building suite_decl.h"
)
add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    DEPENDS build_suit_decl
)


#  Generating suite_list.h  Will rebuild every time 'make' is run
add_custom_target(build_suite_list ALL
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_decl.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "building suite_list.h"
)
add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    DEPENDS build_suite_list
)

add_library(unit_tests STATIC
    ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    sfip_test.cc
    sfrf_test.cc
    sfrt_test.cc
    sfthd_test.cc
    unit_test.cc
    unit_test.h
)

target_link_libraries(unit_tests
    ${CHECK_LIBRARIES}
    ${LIBRT}
)

set_source_files_properties( unit_test.cc PROPERTIES
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
)

endif()
