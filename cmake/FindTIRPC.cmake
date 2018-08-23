# If on a musl llvm based system we need to use libtirpc for rpcent
# This is being added as part of porting to Alpine Linux for minimal Docker containers

find_package(PkgConfig)
pkg_check_modules(PKG_HINT libtirpc)

find_path (TIRPC_INCLUDE_DIR
    NAME tirpc/rpc/rpcent.h
    HINTS ${TIRPC_INCLUDE_DIR_HINT} ${PKG_HINT_INCLUDE_DIRS}
)

if (TIRPC_INCLUDE_DIR)
    find_library(TIRPC_LIBRARY
        NAMES tirpc
        HINTS ${TIRPC_LIBRARIES_DIR_HINT} ${PKG_HINT_LIBRARY_DIRS}
    )
else()
    set(TIRPC_INCLUDE_DIR "")
endif()

if (TIRPC_LIBRARY)
    set(HAVE_TIRPC "1")

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(TIRPC
        TIRPC_INCLUDE_DIR TIRPC_LIBRARY
    )

    mark_as_advanced(TIRPC_INCLUDE_DIR TIRPC_LIBRARY)
else()
    set(TIRPC_LIBRARY "")
endif()

