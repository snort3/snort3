find_path(NUMA_INCLUDE_DIRS numa.h)
find_library(NUMA_LIBRARIES NAMES numa)

if(NUMA_INCLUDE_DIRS AND NUMA_LIBRARIES)
    set(NUMA_FOUND TRUE)
    set(NUMA_LIBRARIES ${NUMA_LIBRARIES})
    set(NUMA_INCLUDE_DIRS ${NUMA_INCLUDE_DIRS})
endif()

if (NOT NUMA_FOUND)
    find_package(PkgConfig)
    pkg_check_modules(PC_NUMA libnuma)

    if(PC_NUMA_FOUND)
        set(NUMA_FOUND TRUE)
        set(NUMA_INCLUDE_DIRS ${PC_NUMA_INCLUDEDIR} ${PC_NUMA_INCLUDE_DIRS})
        set(NUMA_LIBRARIES ${PC_NUMA_LIBDIR} ${PC_NUMA_LIBRARY_DIRS})
    endif()
endif()

if(NUMA_FOUND)
    set(HAVE_NUMA "1")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NUMA DEFAULT_MSG NUMA_LIBRARIES NUMA_INCLUDE_DIRS)

mark_as_advanced(NUMA_INCLUDE_DIRS NUMA_LIBRARIES)