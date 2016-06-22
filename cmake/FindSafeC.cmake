find_path (SAFEC_INCLUDE_DIR
    NAMES libsafec/safe_lib.h
)

if (SAFEC_INCLUDE_DIR)
    find_library(SAFEC_LIBRARIES
        NAMES safec-1.0
    )
else()
    set(SAFEC_INCLUDE_DIR "")
endif()

if (SAFEC_LIBRARIES)
    set(HAVE_SAFEC "1")
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(SafeC
    REQUIRED_VARS SAFEC_INCLUDE_DIR SAFEC_LIBRARIES
)

