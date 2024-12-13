find_library(ML_LIBRARIES NAMES ml_static HINTS ${ML_LIBRARIES_DIR_HINT})
find_path(ML_INCLUDE_DIRS libml.h HINTS ${ML_INCLUDE_DIR_HINT})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(ML
    DEFAULT_MSG
    ML_LIBRARIES
    ML_INCLUDE_DIRS
)

if (ML_FOUND AND NOT USE_LIBML_MOCK)
    set(HAVE_LIBML TRUE)
endif()
