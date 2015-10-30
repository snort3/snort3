
find_path (HS_INCLUDE_DIR NAMES hs/hs_compile.h)

find_library(HS_LIBRARIES NAMES hs)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HS REQUIRED_VARS HS_INCLUDE_DIR HS_LIBRARIES)

mark_as_advanced(HS_INCLUDE_DIR HS_LIBRARIES)


