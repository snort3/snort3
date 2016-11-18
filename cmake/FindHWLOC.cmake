
find_package(PkgConfig)
pkg_check_modules(PC_HWLOC hwloc)

if (NOT PC_HWLOC_FOUND)
    message(SEND_ERROR
        "\n\tERROR!  hwloc library not found.\n"
        "\tGet it from https://www.open-mpi.org/projects/hwloc/\n"
    )
endif()

find_path(HWLOC_INCLUDE_DIRS hwloc.h
    HINTS ${PC_HWLOC_INCLUDEDIR} ${PC_HWLOC_INCLUDE_DIRS})
find_library(HWLOC_LIBRARIES NAMES hwloc
    HINTS ${PC_HWLOC_LIBDIR} ${PC_HWLOC_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HWLOC DEFAULT_MSG HWLOC_LIBRARIES HWLOC_INCLUDE_DIRS)

mark_as_advanced(HWLOC_INCLUDE_DIRS HWLOC_LIBRARIES)
