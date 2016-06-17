
set(ERROR_MESSAGE
    "Unable to find sfbpf!!"
)

find_path (SFBPF_INCLUDE_DIR
    NAMES sfbpf.h
    HINTS ${DAQ_INCLUDE_DIR_HINT}
    NO_SYSTEM_ENVIRONMENT_PATH
)

find_library(SFBPF_LIBRARIES
    NAMES sfbpf
    HINTS ${DAQ_LIBRARIES_DIR_HINT}      # user-specified option in ./configure_cmake.sh
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SFBPF
    REQUIRED_VARS SFBPF_INCLUDE_DIR SFBPF_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    SFBPF_INCLUDE_DIR
    SFBPF_LIBRARIES 
)
