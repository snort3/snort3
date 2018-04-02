# map cmake options to compiler defines and do miscellaneous further configuration work
# cmake options are defined in cmake/create_options.cmake

include(CheckCXXCompilerFlag)

# debugging

# FIXIT-L Properly handle NDEBUG through CMAKE_BUILD_TYPE
if ( ENABLE_DEBUG )
    string ( APPEND DEBUGGING_C_FLAGS " -g -DDEBUG" )
else ()
    string ( APPEND DEBUGGING_C_FLAGS " -DNDEBUG" )
endif ( ENABLE_DEBUG )

if ( ENABLE_GDB )
    string ( APPEND DEBUGGING_C_FLAGS " -g -ggdb" )
endif ( ENABLE_GDB )

# ASAN and TSAN are mutually exclusive, so have them absolutely set SANITIZER_*_FLAGS first.
if ( ENABLE_ADDRESS_SANITIZER )
    set ( ASAN_CXX_FLAGS "-fsanitize=address -fno-omit-frame-pointer" )
    set ( ASAN_LINKER_FLAGS "-fsanitize=address" )
    set ( CMAKE_REQUIRED_FLAGS "${ASAN_LINKER_FLAGS}" )
    check_cxx_compiler_flag ( "${ASAN_CXX_FLAGS}" HAVE_ADDRESS_SANITIZER )
    unset ( CMAKE_REQUIRED_FLAGS )
    if ( HAVE_ADDRESS_SANITIZER )
        set ( SANITIZER_CXX_FLAGS "${ASAN_CXX_FLAGS}" )
        set ( SANITIZER_LINKER_FLAGS "${ASAN_LINKER_FLAGS}" )
    else ()
        message ( SEND_ERROR "Could not enable the address sanitizer!" )
    endif ()
endif ( ENABLE_ADDRESS_SANITIZER )

if ( ENABLE_THREAD_SANITIZER )
    set ( TSAN_CXX_FLAGS "-fsanitize=thread -fno-omit-frame-pointer" )
    set ( TSAN_LINKER_FLAGS "-fsanitize=thread" )
    set ( CMAKE_REQUIRED_FLAGS "${TSAN_LINKER_FLAGS}" )
    check_cxx_compiler_flag ( "${TSAN_CXX_FLAGS}" HAVE_THREAD_SANITIZER )
    unset ( CMAKE_REQUIRED_FLAGS )
    if ( HAVE_THREAD_SANITIZER )
        set ( SANITIZER_CXX_FLAGS "${TSAN_CXX_FLAGS}" )
        set ( SANITIZER_LINKER_FLAGS "${TSAN_LINKER_FLAGS}" )
    else ()
        message ( SEND_ERROR "Could not enable the thread sanitizer!" )
    endif ()
endif ( ENABLE_THREAD_SANITIZER )

if ( ENABLE_UB_SANITIZER )
    set ( UBSAN_CXX_FLAGS "-fsanitize=undefined -fno-sanitize=alignment -fno-omit-frame-pointer" )
    set ( UBSAN_LINKER_FLAGS "-fsanitize=undefined -fno-sanitize=alignment" )
    set ( CMAKE_REQUIRED_FLAGS "${UBSAN_LINKER_FLAGS}" )
    check_cxx_compiler_flag ( "${UBSAN_CXX_FLAGS}" HAVE_UB_SANITIZER )
    unset ( CMAKE_REQUIRED_FLAGS )
    if ( HAVE_UB_SANITIZER )
        string ( APPEND SANITIZER_CXX_FLAGS " ${UBSAN_CXX_FLAGS}" )
        string ( APPEND SANITIZER_LINKER_FLAGS " ${UBSAN_LINKER_FLAGS}" )
    else ()
        message ( SEND_ERROR "Could not enable the undefined behavior sanitizer!" )
    endif ()
endif ( ENABLE_UB_SANITIZER )

if ( ENABLE_CODE_COVERAGE )
    include(${CMAKE_MODULE_PATH}/CodeCoverage.cmake)
endif ( ENABLE_CODE_COVERAGE )


# Accumulate extra flags and libraries
#[[
message("
    DEBUGGING_C_FLAGS = ${DEBUGGING_C_FLAGS}
    SANITIZER_CXX_FLAGS = ${SANITIZER_CXX_FLAGS}
    SANITIZER_LINKER_FLAGS = ${SANITIZER_LINKER_FLAGS}
    COVERAGE_COMPILER_FLAGS = ${COVERAGE_COMPILER_FLAGS}
    COVERAGE_LINKER_FLAGS = ${COVERAGE_LINKER_FLAGS}
    COVERAGE_LIBRARIES = ${COVERAGE_LIBRARIES}
")
]]
set ( EXTRA_C_FLAGS "${EXTRA_C_FLAGS} ${HARDENED_CXX_FLAGS} ${DEBUGGING_C_FLAGS} ${SANITIZER_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}" )
set ( EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} ${HARDENED_CXX_FLAGS} ${DEBUGGING_C_FLAGS} ${SANITIZER_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}" )
set ( EXTRA_LINKER_FLAGS "${EXTRA_LINKER_FLAGS} ${HARDENED_LINKER_FLAGS} ${SANITIZER_LINKER_FLAGS} ${COVERAGE_LINKER_FLAGS}" )
foreach (EXTRA_LIBRARY IN LISTS COVERAGE_LIBRARIES)
    list ( APPEND EXTRA_LIBRARIES ${EXTRA_LIBRARY} )
endforeach ()
