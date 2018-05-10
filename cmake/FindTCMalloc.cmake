
find_package(PkgConfig)
pkg_check_modules(PC_TCMALLOC libtcmalloc)

find_library(TCMALLOC_LIBRARIES NAMES tcmalloc tcmalloc_minimal
    HINTS ${PC_TCMALLOC_LIBDIR} ${PC_TCMALLOC_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TCMalloc REQUIRED_VARS TCMALLOC_LIBRARIES VERSION_VAR PC_TCMALLOC_VERSION)

mark_as_advanced(TCMALLOC_CFLAGS TCMALLOC_LIBRARIES)
