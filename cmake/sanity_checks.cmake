include(CheckIncludeFileCXX)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CheckLibraryExists)
include(CheckCXXSourceCompiles)


#UNCONVERTED AUTOTOOL OPTION

#AC_FUNC_ALLOCA


include (TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)


#check include files
check_include_file_cxx("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file_cxx("fcntl.h" HAVE_FCNTL_H)
check_include_file_cxx("inttypes.h" HAVE_INTTYPES_H)
check_include_file_cxx("libintl.h" HAVE_LIBINTL_H)
check_include_file_cxx("limits.h" HAVE_LIMITS_H)
check_include_file_cxx("malloc.h" HAVE_MALLOC_H)
check_include_file_cxx("netdb.h" HAVE_NETDB_H)
check_include_file_cxx("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file_cxx("stddef.h" HAVE_STDDEF_H)
check_include_file_cxx("stdint.h" HAVE_STDINT_H)
check_include_file_cxx("stdlib.h" HAVE_STDLIB_H)
check_include_file_cxx("string.h" HAVE_STRING_H)
check_include_file_cxx("strings.h" HAVE_STRINGS_H)
check_include_file_cxx("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file_cxx("sys/time.h" HAVE_SYS_TIME_H)
check_include_file_cxx("syslog.h" HAVE_SYSLOG_H)
check_include_file_cxx("unistd.h" HAVE_UNISTD_H)
check_include_file_cxx("wchar.h" HAVE_WCHAR_H)



# UNCONVERTED AUTOTOOL OPTIONS

#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_FUNC_STRERROR_R
#AC_FUNC_STRTOD


set (CMAKE_REQUIRED_INCLUDES "${CMAKE_REQUIRED_INCLUDES} unistd.h")
check_function_exists(chown HAVE_CHOWN)
check_function_exists(fork HAVE_WORKING_FORK)
check_function_exists(vfork HAVE_WORKING_VFORK)
check_function_exists(malloc HAVE_FORK)


check_function_exists(endgrent HAVE_ENDGRENT)
check_function_exists(endpwent HAVE_ENDPWENT)
check_function_exists(ftruncate HAVE_FTRUNCATE)
check_function_exists(getcwd HAVE_GETCWD)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_function_exists(inet_ntoa HAVE_INET_NTOA)
check_function_exists(isascii HAVE_ISASCII)
check_function_exists(localtime_r HAVE_LOCALTIME_R)
check_function_exists(memchr HAVE_MEMCHR)
check_function_exists(memmove HAVE_MEMMOVE)
check_function_exists(memset HAVE_MEMSET)
check_function_exists(mkdir HAVE_MKDIR)
check_function_exists(select HAVE_SELECT)
check_function_exists(socket HAVE_SOCKET)
check_function_exists(strcasecmp HAVE_STRCASECMP)
check_function_exists(strchr HAVE_STRCHR)
check_function_exists(strerror HAVE_STRERROR)
check_function_exists(strncasecmp HAVE_STRNCASECMP)
check_function_exists(strrchr HAVE_STRRCHR)
check_function_exists(strstr HAVE_STRSTR)
check_function_exists(strtol HAVE_STRTOL)
check_function_exists(strtoul HAVE_STRTOUL)

set (CMAKE_REQUIRED_INCLUDES)




#--------------------------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.
#--------------------------------------------------------------------------

check_type_size(int8_t INT8_T)
check_type_size(int16_t INT16_T)
check_type_size(int32_t INT32_T)
check_type_size(int64_t INT64_T)
check_type_size(uint8_t UINT8_T)
check_type_size(uint16_t UINT16_T)
check_type_size(uint32_t UINT32_T)
check_type_size(uint64_t UINT64_T)
check_type_size("char" SIZEOF_CHAR)
check_type_size("short" SIZEOF_SHORT)
check_type_size("int" SIZEOF_INT)
check_type_size("unsigned int" SIZEOF_UNSIGNED_INT)
check_type_size("long int" SIZEOF_LONG_INT)
check_type_size("unsigned long int" SIZEOF_UNSIGNED_LONG_INT)
check_type_size("long long int" SIZEOF_LONG_LONG_INT)
check_type_size("unsigned long long int" SIZEOF_UNSIGNED_LONG_LONG_INT)


check_type_size("uid_t" UID_T)
check_type_size("pid_t" PID_T)
check_type_size("size_t" SIZE_T)
check_type_size("ssize_t" SSIZE_T)
check_type_size("mode_t" MODE_T)

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
