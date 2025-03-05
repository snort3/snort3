find_package(PkgConfig)
pkg_check_modules(PC_NUMA numa>=2.0.14)

if(PC_NUMA_FOUND)
    find_path(NUMA_INCLUDE_DIRS 
        numa.h
        HINTS ${NUMA_INCLUDE_DIR_HINT} ${PC_NUMA_INCLUDEDIR}
    )
    find_library(NUMA_LIBRARIES
        NAMES numa
        HINTS ${NUMA_LIBRARIES_DIR_HINT} ${PC_NUMA_LIBDIR}
    )

    if(NUMA_INCLUDE_DIRS AND NUMA_LIBRARIES)
        set(NUMA_FOUND TRUE)
        set(NUMA_LIBRARIES ${NUMA_LIBRARIES})
        set(NUMA_INCLUDE_DIRS ${NUMA_INCLUDE_DIRS})
    endif()
endif()


if(NUMA_FOUND)
    set(HAVE_NUMA "1")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NUMA DEFAULT_MSG NUMA_LIBRARIES NUMA_INCLUDE_DIRS)

mark_as_advanced(NUMA_INCLUDE_DIRS NUMA_LIBRARIES)
