

set(ERROR_MESSAGE
    "Unable to find libcheck!!  Install libcheck before running
     'make check' command"
)

find_library(CHECK_LIBRARY
    NAMES check
)

find_path (CHECK_INCLUDE_DIRS
    NAMES check.h
)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CHECK
    REQUIRED_VARS CHECK_INCLUDE_DIRS CHECK_INCLUDE_DIRS
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)



mark_as_advanced(
    CHECK_INCLUDE_DIRS 
    CHECK_LIBRARIES 
)


