include(CheckIncludeFileCXX)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CheckLibraryExists)
include(CheckCXXSourceCompiles)

include (TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

#--------------------------------------------------------------------------
# Checks for system library functions
#--------------------------------------------------------------------------

check_function_exists(mallinfo HAVE_MALLINFO)
check_function_exists(malloc_trim HAVE_MALLOC_TRIM)
check_function_exists(memrchr HAVE_MEMRCHR)
check_function_exists(sigaction HAVE_SIGACTION)

#--------------------------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.
#--------------------------------------------------------------------------

check_type_size("long int" SIZEOF_LONG_INT)
check_type_size("unsigned long int" SIZEOF_UNSIGNED_LONG_INT)


# vvvvvvvvv  INLINE TEST vvvvvvvvv

# Taken and edited from www.cmake.org/wiki/CMakeTestInline

FOREACH(KEYWORD "inline" "__inline__" "__inline")
    IF(NOT DEFINED INLINE)
        check_cxx_source_compiles(
            "
            typedef int foo_t;
            static inline foo_t static_foo(){return 0;}
            foo_t foo(){return 0;}
            int main(int argc, char *argv[]){return 0;}
            "
            INLINE
        )
        IF(INLINE)
            add_definitions("-Dinline=${KEYWORD}")
            break()
        ENDIF(INLINE)
    ENDIF(NOT DEFINED INLINE)
ENDFOREACH(KEYWORD)
IF(NOT DEFINED INLINE)
    add_definitions("-Dinline=")
ENDIF(NOT DEFINED INLINE)

# ^^^^^^^^^  INLINE TEST ^^^^^^^^^


# vvvvvvvvv  RESTRICT TEST vvvvvvvvv


# Taken directly from http://www.cmake.org/pipermail/cmake/2013-January/053113.html

# Check for restrict keyword
# Builds the macro A_C_RESTRICT form automake
foreach(ac_kw __restrict __restrict__ _Restrict restrict)
    check_cxx_source_compiles(
        "
        typedef int * int_ptr;
        int foo (int_ptr ${ac_kw} ip) {
        return ip[0];
        }
        int main(){
        int s[1];
        int * ${ac_kw} t = s;
        t[0] = 0;
        return foo(t);
        }
        "
        RESTRICT
    )
    if(RESTRICT)
        set(ac_cv_c_restrict ${ac_kw})
        break()
    endif()
endforeach()
if(RESTRICT)
    add_definitions("-Drestrict=${ac_cv_c_restrict}")
else()
    add_definitions("-Drestrict=")
endif()

# ^^^^^^^^^  RESTRICT TEST ^^^^^^^^^




# set library variables
if (HS_FOUND)
    check_library_exists (${HS_LIBRARIES} hs_scan "" HAVE_HYPERSCAN)
endif()

if (DEFINED LIBLZMA_LIBRARIES)
    check_library_exists (${LIBLZMA_LIBRARIES} lzma_code "" HAVE_LZMA)
endif()

if (ICONV_FOUND)
    # Not actually a sanity check at the moment...
    set (HAVE_ICONV "1")
endif()
