find_package(PkgConfig)
pkg_check_modules(PC_ML libml_static>=2.0.0)

find_path(ML_INCLUDE_DIRS
    libml.h
    HINTS ${ML_INCLUDE_DIR_HINT} ${PC_ML_INCLUDEDIR}
)

find_library(ML_LIBRARIES
    NAMES ml_static
    HINTS ${ML_LIBRARIES_DIR_HINT} ${PC_ML_LIBDIR}
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(ML
    DEFAULT_MSG
    ML_INCLUDE_DIRS
    ML_LIBRARIES
)

if (ML_FOUND AND NOT USE_LIBML_MOCK)
    set(HAVE_LIBML TRUE)
endif()
