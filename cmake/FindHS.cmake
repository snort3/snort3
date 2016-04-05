
find_package(PkgConfig)
pkg_check_modules(PC_HYPERSCAN libhs)

# Use HS_INCLUDE_DIR and HS_LIBRARY_DIR from configure_cmake.sh as primary hints
# and then package config information after that.
find_path(HS_INCLUDE_DIRS hs_compile.h
    HINTS ${HS_INCLUDE_DIR} ${PC_HYPERSCAN_INCLUDEDIR} ${PC_HYPERSCAN_INCLUDE_DIRS})
find_library(HS_LIBRARIES NAMES hs
    HINTS ${HS_LIBRARIES_DIR} ${PC_HYPERSCAN_LIBDIR} ${PC_HYPERSCAN_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(hs DEFAULT_MSG HS_LIBRARIES HS_INCLUDE_DIRS)

mark_as_advanced(HS_INCLUDE_DIRS HS_LIBRARIES)
