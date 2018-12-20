# Find the headers and library required for iconv functions.
# Libc-based iconv test lifted from the upstream CMake FindIconv.cmake module.

# First, try to find the iconv header, looking in the hinted directory first.
find_path(ICONV_INCLUDE_DIR
    NAMES iconv.h
    HINTS ${ICONV_INCLUDE_DIR_HINT}
)

if (ICONV_INCLUDE_DIR)
    # Test to see if iconv is available from libc and matches the header we found.
    # Assume that an explicit include dir or library dir hint means we're not going
    # to be using a libc implementation.
    if (UNIX AND NOT ICONV_INCLUDE_DIR_HINT AND NOT ICONV_LIBRARIES_DIR_HINT)
        include(CMakePushCheckState)
        cmake_push_check_state(RESET)
        # Make sure we're using the iconv.h we found above
        set(CMAKE_REQUIRED_INCLUDES ${ICONV_INCLUDE_DIR})
        # We always suppress the message here: Otherwise on supported systems
        # not having iconv in their C library (e.g. those using libiconv)
        # would always display a confusing "Looking for iconv - not found" message
        set(CMAKE_FIND_QUIETLY TRUE)
        # The following code will not work, but it's sufficient to see if it compiles.
        # Note: libiconv will define the iconv functions as macros, so CheckSymbolExists
        # will not yield correct results.
        set(ICONV_IMPLICIT_TEST_CODE
            "
            #include <stddef.h>
            #include <iconv.h>
            int main() {
                char *a, *b;
                size_t i, j;
                iconv_t ic;
                ic = iconv_open(\"to\", \"from\");
                iconv(ic, &a, &i, &b, &j);
                iconv_close(ic);
            }
            "
        )
        if (CMAKE_C_COMPILER_LOADED)
            include(CheckCSourceCompiles)
            check_c_source_compiles("${ICONV_IMPLICIT_TEST_CODE}" ICONV_IS_BUILT_IN)
        elseif (CMAKE_CXX_COMPILER_LOADED)
            include(CheckCXXSourceCompiles)
            check_cxx_source_compiles("${ICONV_IMPLICIT_TEST_CODE}" ICONV_IS_BUILT_IN)
        endif()
        cmake_pop_check_state()
    endif()

    if (NOT ICONV_IS_BUILT_IN)
        find_library(ICONV_LIBRARY
            NAMES iconv libiconv
            HINTS ${ICONV_LIBRARIES_DIR_HINT}
        )
    endif()
else()
    unset(ICONV_INCLUDE_DIR)
endif()

include(FindPackageHandleStandardArgs)
if (NOT ICONV_IS_BUILT_IN)
  find_package_handle_standard_args(ICONV REQUIRED_VARS ICONV_LIBRARY ICONV_INCLUDE_DIR)
else()
  find_package_handle_standard_args(ICONV REQUIRED_VARS ICONV_INCLUDE_DIR)
endif()

mark_as_advanced(ICONV_INCLUDE_DIR)
mark_as_advanced(ICONV_LIBRARY)

