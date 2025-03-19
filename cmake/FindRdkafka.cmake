find_package(PkgConfig REQUIRED)
pkg_check_modules(PC_RDKAFKA rdkafka)

if (PC_RDKAFKA_FOUND)
    set(RDKAFKA_LIBRARIES ${PC_RDKAFKA_LIBRARIES})
    set(RDKAFKA_INCLUDE_DIRS ${PC_RDKAFKA_INCLUDE_DIRS})
else()
    message(WARNING "librdkafka not found using pkg-config. Ensure it is installed.")
endif()

find_path(RDKAFKA_INCLUDE_DIR
    NAMES rdkafka.h
    HINTS ${RDKAFKA_INCLUDE_DIR_HINT} ${PC_RDKAFKA_INCLUDEDIR} ${CMAKE_SOURCE_DIR}/include /usr/include/librdkafka /usr/local/include
)

find_library(RDKAFKA_LIBRARY
    NAMES rdkafka
    HINTS ${RDKAFKA_INCLUDE_LIB_HINT} ${PC_RDKAFKA_LIBDIR} ${CMAKE_SOURCE_DIR}/lib /usr/lib /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    Rdkafka
    REQUIRED_VARS RDKAFKA_INCLUDE_DIR RDKAFKA_LIBRARY
)

if (RDKAFKA_FOUND)
    set(HAVE_RDKAFKA TRUE)
    message(STATUS "librdkafka found: ${RDKAFKA_LIBRARIES}")
else()
    message(FATAL_ERROR "librdkafka not found! Please ensure the library is installed.")
endif()

mark_as_advanced(
    RDKAFKA_INCLUDE_DIR
    RDKAFKA_LIBRARY
)
