# Find the native UUID include file and library.

find_package(PkgConfig)
pkg_check_modules(PC_UUID uuid)

if (PC_UUID_FOUND)
    set(UUID_LIBRARY_NAME ${PC_UUID_LIBRARIES})
else()
    set(UUID_LIBRARY_NAME "uuid")
endif()

find_path (UUID_INCLUDE_DIR
    NAMES uuid.h
    HINTS ${UUID_INCLUDE_DIR_HINT} ${PC_UUID_INCLUDEDIR} ${PC_UUID_INCLUDE_DIRS}
    PATH_SUFFIXES uuid
)

if (UUID_LIBRARY_NAME)
    find_library(UUID_LIBRARY
        NAMES ${UUID_LIBRARY_NAME}
        HINTS ${UUID_LIBRARIES_DIR_HINT} ${PC_UUID_LIBDIR} ${PC_UUID_LIBRARY_DIRS}
    )
    set(REQUIRED_UUID_LIBRARY "UUID_LIBRARY")
else()
    set(REQUIRED_UUID_LIBRARY "")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    UUID
    REQUIRED_VARS
        UUID_INCLUDE_DIR ${REQUIRED_UUID_LIBRARY}
)

mark_as_advanced(
    UUID_INCLUDE_DIR
    UUID_LIBRARY
)

