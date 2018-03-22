#  All of the possible user options.  All of these options will show up
#  in the CACHE.  If you'd like to change one of these values,
#  use `ccmake ${PATH_TO_SOURCE}`.
#  Alternatively, you can pass them to cmake on the command line using
#  the '-D' flag:
#      cmake -DENABLE_FOO=ON -DCMAKE_INSTALL_PREFIX=/my/install/path $cmake_src_path

# debugging
option ( ENABLE_DEBUG "Enable debugging options (bugreports and developers only)" OFF )
option ( ENABLE_GDB "Enable gdb debugging information" ON )
option ( ENABLE_ADDRESS_SANITIZER "enable address sanitizer support" OFF )
option ( ENABLE_THREAD_SANITIZER "enable thread sanitizer support" OFF )
option ( ENABLE_UB_SANITIZER "enable undefined behavior sanitizer support" OFF )
option ( ENABLE_CODE_COVERAGE "Whether to enable code coverage support" OFF )

