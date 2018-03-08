#
# Loosely based on:
#   https://raw.githubusercontent.com/peti/autoconf-archive/master/m4/ax_code_coverage.m4
#       - and -
#   https://raw.githubusercontent.com/bilke/cmake-modules/master/CodeCoverage.cmake
#

find_program( GCOV_PATH gcov )

if(NOT GCOV_PATH)
    message(FATAL_ERROR "gcov not found! Aborting...")
endif()

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
    if("${CMAKE_CXX_COMPILER_VERSION}" VERSION_LESS 3)
        message(FATAL_ERROR "Clang version must be 3.0.0 or greater! Aborting...")
    endif()
elseif(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    message(FATAL_ERROR "Compiler is not GNU gcc! Aborting...")
endif()

set(COVERAGE_COMPILER_FLAGS "-O0 -g -fprofile-arcs -ftest-coverage")

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(COVERAGE_LINKER_FLAGS "")
    set(COVERAGE_LIBRARIES "gcov")
else()
    set(COVERAGE_LINKER_FLAGS "--coverage")
    set(COVERAGE_LIBRARIES "")
endif()

mark_as_advanced(
    COVERAGE_COMPILER_FLAGS
    COVERAGE_LINKER_FLAGS
    COVERAGE_LIBRARIES
)
