###################################################################
# - Find the Dumb (not so!) Library: dnet
# Find the DUMBNET includes and library
# http://code.google.com/p/libdnet/
#
# The environment variable DUMBNETDIR allows to specficy where to find 
# libdnet in non standard location.
#  
#  DNET_INCLUDE_DIR - where to find dnet.h, etc.
#  DNET_LIBRARIES   - List of libraries when using dnet.
#  DNET_FOUND       - True if dnet found.



set(ERROR_MESSAGE
    "   
    ERROR!  dnet header not found, go get it from
    http://code.google.com/p/libdnet/ or use the --with-dnet-*
    options, if you have it installed in an unusual place.  You can also
    set the DNET_DIR shell variable to dnets root installation directory"
)


find_path(DNET_INCLUDE_DIR 
  NAMES dnet.h dumbnet.h
  HINTS ENV DNETDIR
)

# Search for library twice.  The first time using the custom path, second time
# using standard paths
find_library(DNET_LIBRARIES
    NAMES dnet dumbnet
    PATHS ${DNET_LIBRARIES_DIR}
    NO_DEFAULT_PATH
)
find_library(DNET_LIBRARIES
    NAMES dnet dumbnet
)



include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DNET 
    REQUIRED_VARS DNET_INCLUDE_DIR DNET_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    DNET_INCLUDE_DIR
    DNET_LIBRARIES
)
