

#  All of the possible user options.  All of these optinos will show up
#  in the CACHE.  If you'd like to change one of these values,
#  use `ccmamke ${PATH_TO_SOURCE}`.


option (STATIC_CODECS "include decoders in binary?" ON)
option (STATIC_INSPECTORS "include inspectors in binary" ON)
option (STATIC_LOGGERS "include loggers in binary" ON)
option (STATIC_IPS_ACTIONS "include internal ips actions in binary" ON)
option (STATIC_IPS_OPTIONS "include ips options in binary" ON)
option (STATIC_SEARCH_ENGINES "include search engines in binary" ON)
option (BUILD_CONTROL_SOCKET "Enable the control socket (Linux only)" OFF)
option (BUILD_SIDE_CHANNEL "Enable the side channel (Linux only)" OFF)
option (ENABLE_STATIC_DAQ "Link static DAQ modules" ON)
option (ENABLE_VALGRIND "Only use if you are testing with valgrind" OFF)
option (ENABLE_PPM "Disable packet/rule performance monitor" OFF)
option (ENABLE_PPM_TEST "Enable packet/rule performance monitor for readback" OFF)
option (ENABLE_PERFPROFILING "Disable preprocessor and rule performance profiling" OFF)
option (ENABLE_LINUX_SMP_STATS "Enable statistics reporting through proc" OFF)
option (ENABLE_PTHREAD "Disable pthread support" ON)
option (ENABLE_DEBUG_MSGS "Enable debug printing options (bugreports and developers only)" OFF)
option (ENABLE_DEBUG "Enable debugging options (bugreports and developers only)" OFF)
option (ENABLE_GDB "Enable gdb debugging information" OFF)
option (ENABLE_PROFILE "Enable profiling options (developers only)" OFF)
option (ENABLE_SHELL "enable shell support" OFF)
option (ENABLE_COREFILES "Prevent Snort from generating core files" ON)
option (BUILD_HA "Enable high-availability state sharing" OFF)
option (ENABLE_INTEL_SOFT_CPM "Enable Intel Soft CPM support" OFF)
option (ENABLE_LARGE_PCAP "Enable support for pcaps larger than 2 GB" OFF)
option (BUILD_SIDE_CHANNEL "Build the side channel library" OFF)
option (BUILD_UNIT_TESTS "Build Snort++ unit tests" OFF)
option (BUILD_PIGLET "Build Piglet test harness" OFF)
option (BUILD_EXTRA_PLUGINS "Build and test the plugins in the extra directory" OFF)
option (MAKE_HTML_DOC "Create the HTML documentation" ON)
option (MAKE_PDF_DOC "Create the PDF documentation" ON)
option (MAKE_TEXT_DOC "Create the text documentation" ON)

option (STATIC_PIGLETS "include piglet plugins in binary" ON)
option (BUILD_PIGLET "Build Piglet test harness" OFF)

set (SIGNAL_SNORT_RELOAD "" CACHE STRING "set the SIGNAL_SNORT_RELOAD value.  THIS NUMBER MUST BE AN INTEGER!!")
set (SIGNAL_SNORT_DUMP_STATS "" CACHE STRING "set the SIGNAL_SNORT_DUMP_STATS value. THIS NUMBER MUST BE AN INTEGER!!")
set (SIGNAL_SNORT_ROTATE_STATS "" CACHE STRING "set the SIGNAL_SNORT_ROTATE_STATS value. THIS NUMBER MUST BE AN INTEGER!!")
set (SIGNAL_SNORT_READ_ATTR_TBL "" CACHE STRING "set the SIGNAL_SNORT_READ_ATTR_TBL value. THIS NUMBER MUST BE AN INTEGER!!")


#Setting default directories...appended to INSTALL_PREFIX unless a full path is provided
set (SNORT_DATA_DIR share/doc/${CMAKE_PROJECT_NAME})

