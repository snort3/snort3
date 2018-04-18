# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindIconv
---------

This module finds the ``iconv()`` POSIX.1 functions on the system.
These functions might be provided in the regular C library or externally
in the form of an additional library.

The following variables are provided to indicate iconv support:

.. variable:: ICONV_FOUND

  Variable indicating if the iconv support was found.

.. variable:: Iconv_INCLUDE_DIRS

  The directories containing the iconv headers.

.. variable:: Iconv_LIBRARIES

  The iconv libraries to be linked.

.. variable:: Iconv_IS_BUILT_IN

  A variable indicating whether iconv support is stemming from the
  C library or not. Even if the C library provides `iconv()`, the presence of
  an external `libiconv` implementation might lead to this being false.

The following cache variables may also be set:

.. variable:: ICONV_INCLUDE_DIR

  The directory containing the iconv headers.

.. variable:: ICONV_LIBRARY

  The iconv library (if not implicitly given in the C library).

.. note::
  On POSIX platforms, iconv might be part of the C library and the cache
  variables ``ICONV_INCLUDE_DIR`` and ``ICONV_LIBRARY`` might be empty.

#]=======================================================================]
#
# This file was modified to work in Snort build environment
#

include(CMakePushCheckState)
if(CMAKE_C_COMPILER_LOADED)
  include(CheckCSourceCompiles)
elseif(CMAKE_CXX_COMPILER_LOADED)
  include(CheckCXXSourceCompiles)
else()
  # If neither C nor CXX are loaded, implicit iconv makes no sense.
  set(Iconv_IS_BUILT_IN FALSE)
endif()

# iconv can only be provided in libc on a POSIX system.
# If any cache variable is already set, we'll skip this test.
if(NOT DEFINED Iconv_IS_BUILT_IN)
  if(UNIX AND NOT DEFINED ICONV_INCLUDE_DIR AND NOT DEFINED ICONV_LIBRARY)
    cmake_push_check_state(RESET)
    # We always suppress the message here: Otherwise on supported systems
    # not having iconv in their C library (e.g. those using libiconv)
    # would always display a confusing "Looking for iconv - not found" message
    set(CMAKE_FIND_QUIETLY TRUE)
    # The following code will not work, but it's sufficient to see if it compiles.
    # Note: libiconv will define the iconv functions as macros, so CheckSymbolExists
    # will not yield correct results.
    set(Iconv_IMPLICIT_TEST_CODE
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
    if(CMAKE_C_COMPILER_LOADED)
      check_c_source_compiles("${Iconv_IMPLICIT_TEST_CODE}" Iconv_IS_BUILT_IN)
    else()
      check_cxx_source_compiles("${Iconv_IMPLICIT_TEST_CODE}" Iconv_IS_BUILT_IN)
    endif()
    cmake_pop_check_state()
  else()
    set(Iconv_IS_BUILT_IN FALSE)
  endif()
endif()

if(NOT Iconv_IS_BUILT_IN)
  find_path(ICONV_INCLUDE_DIR
    NAMES "iconv.h"
    DOC "iconv include directory")
  set(Iconv_LIBRARY_NAMES "iconv" "libiconv")
else()
  set(ICONV_INCLUDE_DIR "" CACHE FILEPATH "iconv include directory")
  set(Iconv_LIBRARY_NAMES "c")
endif()

find_library(ICONV_LIBRARY
  NAMES ${Iconv_LIBRARY_NAMES}
  DOC "iconv library (potentially the C library)")

mark_as_advanced(ICONV_INCLUDE_DIR)
mark_as_advanced(ICONV_LIBRARY)

include(FindPackageHandleStandardArgs)
if(NOT Iconv_IS_BUILT_IN)
  find_package_handle_standard_args(ICONV REQUIRED_VARS ICONV_LIBRARY ICONV_INCLUDE_DIR)
else()
  find_package_handle_standard_args(ICONV REQUIRED_VARS ICONV_LIBRARY)
endif()

if(ICONV_FOUND)
  set(CMAKE_REQUIRED_INCLUDES ${ICONV_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${ICONV_LIBRARY})
endif()