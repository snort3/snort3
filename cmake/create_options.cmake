#  All of the possible user options.  All of these options will show up
#  in the CACHE.  If you'd like to change one of these values,
#  use `ccmake ${PATH_TO_SOURCE}`.
#  Alternatively, you can pass them to cmake on the command line using
#  the '-D' flag:
#      cmake -DENABLE_FOO=ON -DCMAKE_INSTALL_PREFIX=/my/install/path $cmake_src_path

# static/dynamic switches
option ( STATIC_CODECS "include codecs in binary" ON )
option ( STATIC_INSPECTORS "include inspectors in binary" ON )
option ( STATIC_LOGGERS "include loggers in binary" ON )
option ( STATIC_IPS_ACTIONS "include ips actions in binary" ON )
option ( STATIC_IPS_OPTIONS "include ips options in binary" ON )
option ( STATIC_SEARCH_ENGINES "include search engines in binary" ON )
option ( ENABLE_STATIC_DAQ "link static DAQ modules" ON )

# features
option ( ENABLE_SHELL "enable shell support" OFF )
option ( ENABLE_APPID_THIRD_PARTY "enable third party appid" OFF )
option ( ENABLE_UNIT_TESTS "enable unit tests" OFF )
option ( ENABLE_PIGLET "enable piglet test harness" OFF )

option ( ENABLE_COREFILES "Prevent Snort from generating core files" ON )
option ( ENABLE_LARGE_PCAP "Enable support for pcaps larger than 2 GB" OFF )
option ( ENABLE_STDLOG "Use file descriptor 3 instead of stdout for alerts" OFF )
option ( ENABLE_TSC_CLOCK "Use timestamp counter register clock (x86 only)" OFF )

# documentation
option ( MAKE_HTML_DOC "Create the HTML documentation" ON )
option ( MAKE_PDF_DOC "Create the PDF documentation" ON )
option ( MAKE_TEXT_DOC "Create the text documentation" ON )
option ( MAKE_DOC "Create documentation" ON )

# security
option ( ENABLE_HARDENED_BUILD "Detect and use compile-time hardening options" OFF )
option ( ENABLE_PIE "Attempt to produce a position-independent executable" OFF )
option ( ENABLE_SAFEC "Use bounds checked functions provided by libsafec" ON )

# debugging
option ( ENABLE_DEBUG_MSGS "Enable debug printing options (bugreports and developers only)" OFF )
option ( ENABLE_DEBUG "Enable debugging options (bugreports and developers only)" OFF )
option ( ENABLE_GDB "Enable gdb debugging information" ON )
option ( ENABLE_PROFILE "Enable profiling options (developers only)" OFF )
option ( DISABLE_SNORT_PROFILER "Disable snort Profiler (developers only)" OFF )
option ( ENABLE_DEEP_PROFILING "Enable deep profiling of snort functions (developers only)" OFF )
option ( DISABLE_MEMORY_MANAGER "Disable snort memory manager (developers only)" OFF )
option ( ENABLE_ADDRESS_SANITIZER "enable address sanitizer support" OFF )
option ( ENABLE_THREAD_SANITIZER "enable thread sanitizer support" OFF )
option ( ENABLE_UB_SANITIZER "enable undefined behavior sanitizer support" OFF )
option ( ENABLE_TCMALLOC "enable using tcmalloc for dynamic memory management" OFF )
option ( ENABLE_CODE_COVERAGE "Whether to enable code coverage support" OFF )

# signals
set (
    SIGNAL_SNORT_RELOAD "SIGHUP"
    CACHE STRING "set the SNORT_RELOAD signal (must be a valid integer or signal name)"
)

set (
    SIGNAL_SNORT_DUMP_STATS "SIGUSR1"
    CACHE STRING "set the SNORT_DUMP_STATS signal (must be a valid integer or signal name)"
)

set (
    SIGNAL_SNORT_ROTATE_STATS "SIGUSR2"
    CACHE STRING "set the SNORT_ROTATE_STATS signal (must be a valid integer or signal name)"
)

set (
    SIGNAL_SNORT_READ_ATTR_TBL "SIGURG"
    CACHE STRING "set the SNORT_READ_ATTR_TBL signal (must be a valid integer or signal name)"
)
