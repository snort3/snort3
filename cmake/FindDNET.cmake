###################################################################
# - Find the Dumb (not so!) Library: dnet
# Find the DUMBNET includes and library
# http://code.google.com/p/libdnet/
#
# The environment variable DUMBNETDIR allows to specficy where to find 
# libdnet in non standard location.
#  
#  DNET_INCLUDE_DIRS - where to find dnet.h, etc.
#  DNET_LIBRARIES   - List of libraries when using dnet.
#  DNET_FOUND       - True if dnet found.



set(ERROR_MESSAGE
    "   
    ERROR!  dnet header not found, go get it from
    http://code.google.com/p/libdnet/ or use the --with-dnet-*
    options, if you have it installed in an unusual place.  You can also
    set the DNET_DIR shell variable to dnets root installation directory"
)


find_program(DNET_CONFIG 
    NAMES dnet-config
    HINTS ENV DNET_DIR
)

# Don't search for the dnet include directories if it is already defined by the user
if(NOT DNET_INCLUDE_DIRS)
    if(DNET_CONFIG)
        EXECUTE_PROCESS(COMMAND ${DNET_CONFIG} --cflags
            OUTPUT_VARIABLE DNET_INCLUDE_DIRS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else(DNET_CONFIG)
      find_path(DNET_INCLUDE_DIRS 
          NAMES dnet.h dumbnet.h
          HINTS ENV DNETDIR
      )

    endif(DNET_CONFIG)
endif(NOT DNET_INCLUDE_DIRS)


# Don't search for the dnet libraries if it is already defined by the user
if(NOT DNET_LIBRARIES)
    if(DNET_CONFIG)
        EXECUTE_PROCESS(COMMAND ${DNET_CONFIG} --libs
            OUTPUT_VARIABLE DNET_LIBRARIES
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )

    else(DNET_CONFIG)
        find_library(DNET_LIBRARIES
            NAMES dnet dumbnet
            HINTS ENV DNETDIR
        )

    endif(DNET_CONFIG)
endif(NOT DNET_LIBRARIES)




include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DNET 
    REQUIRED_VARS DNET_INCLUDE_DIRS DNET_LIBRARIES
    FAIL_MESSAGE "${ERROR_MESSAGE}"
)

mark_as_advanced(
    DNET_INCLUDE_DIRS
    DNET_LIBRARIES
)
unset(DNET_CONFIG CACHE)
