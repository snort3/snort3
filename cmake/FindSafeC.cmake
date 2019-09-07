
find_package(PkgConfig)
pkg_check_modules(PC_SAFEC libsafec)

find_path(SAFEC_INCLUDE_DIR
    NAMES safe_lib.h
    HINTS ${PC_SAFEC_INCLUDEDIR} ${PC_SAFEC_INCLUDE_DIRS}
    NO_SYSTEM_ENVIRONMENT_PATH
)
find_library(SAFEC_LIBRARIES
    NAMES ${PC_SAFEC_LIBRARIES}
    HINTS ${PC_SAFEC_LIBDIR} ${PC_SAFEC_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    SafeC
    REQUIRED_VARS
        SAFEC_INCLUDE_DIR
        SAFEC_LIBRARIES
    VERSION_VAR
        PC_SAFEC_VERSION
)

mark_as_advanced(
    SAFEC_INCLUDE_DIR
    SAFEC_LIBRARIES
)
