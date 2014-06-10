

set(ERROR_MESSAGE
    "Unable to find libcheck!!  Install libcheck before running
     'make check' command"
)


find_path (CHECK_INCLUDE_DIR
    NAMES check.h
)

find_library(CHECK_LIBRARIES
    NAMES check
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CHECK
    REQUIRED_VARS CHECK_INCLUDE_DIR CHECK_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)



mark_as_advanced(
    CHECK_INCLUDE_DIR
    CHECK_LIBRARIES
)


