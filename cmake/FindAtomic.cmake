find_library(ATOMIC_LIBRARIES NAMES atomic
    HINTS ${ATOMIC_LIBRARIES_DIR_HINT})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Atomic DEFAULT_MSG ATOMIC_LIBRARIES)

mark_as_advanced(ATOMIC_LIBRARIES)

if (ATOMIC_LIBRARIES)
    set(HAVE_ATOMIC "1")
endif()
