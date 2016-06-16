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
    options, if you have it installed in an unusual place.
    "
)

# Check for libdumbnet first, then libdnet

find_path(DUMBNET_INCLUDE_DIR dumbnet.h
    HINTS ${DNET_INCLUDE_DIR_HINT})

# If we found libdumbnet header, define HAVE_DUMBNET_H for config.h generation
# and search for libdumbnet.
if (DUMBNET_INCLUDE_DIR)
    set(HAVE_DUMBNET_H "1")
    set(DNET_INCLUDE_DIR ${DUMBNET_INCLUDE_DIR})
    find_library(DNET_LIBRARIES NAMES dumbnet
        HINTS ${DNET_LIBRARIES_DIR_HINT})
else ()
    find_path(DNET_INCLUDE_DIR dnet.h
        HINTS ${DNET_INCLUDE_DIR_HINT})
    find_library(DNET_LIBRARIES NAMES dnet
        HINTS ${DNET_LIBRARIES_DIR_HINT})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DNET 
    REQUIRED_VARS DNET_INCLUDE_DIR DNET_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    DNET_INCLUDE_DIR
    DNET_LIBRARIES
)
