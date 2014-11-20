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
#  HAVE_DUMBNET_H   - True if found dumnet rather than dnet



set(ERROR_MESSAGE
    "   
    ERROR!  dnet header not found, go get it from
    http://code.google.com/p/libdnet/ or use the --with-dnet-*
    options, if you have it installed in an unusual place.  You can also
    set the DNET_DIR shell variable to dnets root installation directory"
)


# Check for libdumbnet first, then libdnet

find_path(DNET_INCLUDE_DIR
  NAMES dumbnet.h
  HINTS ENV DNETDIR
)

# If we found libdument header, define HAVE_DUMBNET_H for config.h generation.
if (DNET_INCLUDE_DIR)
    set(HAVE_DUMBNET_H "YES")
endif()


# Search for library twice.  The first time using the custom path, second time
# using standard paths
find_library(DNET_LIBRARIES
    NAMES dumbnet
    HINTS ${DNET_LIBRARIES_DIR} # user specified option in ./configure_cmake.sh
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)
find_library(DNET_LIBRARIES
    NAMES dumbnet
)


find_path(DNET_INCLUDE_DIR
  NAMES dnet.h
  HINTS ENV DNETDIR
)

find_library(DNET_LIBRARIES
    NAMES dnet
    HINTS ${DNET_LIBRARIES_DIR}
    NO_DEFAULT_PATH
    NO_CMAKE_ENVIRONMENT_PATH
)
find_library(DNET_LIBRARIES
    NAMES dnet
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
