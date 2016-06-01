

set(ERROR_MESSAGE
    "Unable to find sfbpf!!"
)


find_path (SFBPF_INCLUDE_DIR
    NAMES sfbpf.h
)

find_library(SFBPF_LIBRARIES
    NAMES sfbpf
    HINTS ${SFBPF_LIBRARIES_DIR} # user specified option in ./configure_cmake.sh
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)

find_library(SFBPF_LIBRARIES
    NAMES sfbpf
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SFBPF
    REQUIRED_VARS SFBPF_INCLUDE_DIR SFBPF_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

