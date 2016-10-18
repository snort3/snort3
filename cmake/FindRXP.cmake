# Use RXP_INCLUDE_DIR and RXP_LIBRARY_DIR from configure_cmake.sh as primary hints
# and then usual location information after that.
file(GLOB RXP_INCLUDE_SEARCH "/opt/titan_ic_systems/hyperion_sdk_*/tics_dpdk*/x86_64-native-linuxapp-gcc/include")
file(GLOB RXP_LIBRARIES_SEARCH "/opt/titan_ic_systems/hyperion_sdk_*/tics_dpdk*/x86_64-native-linuxapp-gcc/lib")

find_path(RXP_INCLUDE_DIRS rxp.h
    HINTS ${RXP_INCLUDE_DIR} PATHS ${RXP_INCLUDE_SEARCH})
find_library(RXP_LIBRARIES NAMES dpdk
    HINTS ${RXP_LIBRARIES_DIR} PATHS ${RXP_LIBRARIES_SEARCH})

# FIXIT-T: Terrible, terrible hack; our DPDK libs should be somewhere properly discoverable
link_directories(${RXP_LIBRARIES_SEARCH})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(rxp DEFAULT_MSG RXP_LIBRARIES RXP_INCLUDE_DIRS)

mark_as_advanced(RXP_INCLUDE_DIRS RXP_LIBRARIES)
