# Find the native UUID include file and library.

find_package(PkgConfig)
pkg_check_modules(PKG_HINT uuid)

find_path (UUID_INCLUDE_DIR
    NAMES uuid.h
    HINTS ${UUID_INCLUDE_DIR_HINT} ${PKG_HINT_INCLUDE_DIRS}
)

if (UUID_INCLUDE_DIR)
    find_library(UUID_LIBRARY
        NAMES uuid
        HINTS ${UUID_LIBRARIES_DIR_HINT} ${PKG_HINT_LIBRARY_DIRS}
    )
else()
    set(UUID_INCLUDE_DIR "")
endif()

if (UUID_LIBRARY)
    set(HAVE_UUID "1")

    include(FindPackageHandleStandardArgs)

    find_package_handle_standard_args(UUID
        UUID_INCLUDE_DIR UUID_LIBRARY
    )

    mark_as_advanced(UUID_INCLUDE_DIR UUID_LIBRARY)
else()
    set(UUID_LIBRARY "")
endif()

