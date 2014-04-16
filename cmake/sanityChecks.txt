include (CheckIncludeFileCXX)
include (CheckFunctionExists)
include (CheckSymbolExists)
include (CheckTypeSize)
include (CheckLibraryExists)


#Sets the current snort version
set(VERSION ${SNORT_VERSION_MAJOR}.
            ${SNORT_VERSION_MINOR}.
            ${SNORT_VERSION_BUILD}
    )




#check include files
check_include_file_cxx("dlfcn.h" HAVE_DLFCN_H)
check_include_file_cxx("math.h" HAVE_MATH_H)
check_include_file_cxx("memory.h" HAVE_MEMORY_H)
check_include_file_cxx("wchar.h" HAVE_WCHAR_H)
check_include_file_cxx("inttypes.h" HAVE_INTTYPES_H)
check_include_file_cxx("openssl/sha.h" HAVE_OPENSSL_SHA_H)
check_include_file_cxx("paths.h" HAVE_PATHS_H)
check_include_file_cxx("stdint.h" HAVE_STDINT_H)
check_include_file_cxx("stdlib.h" HAVE_STDLIB_H)
check_include_file_cxx("strings.h" HAVE_STRINGS_H)
check_include_file_cxx("string.h" HAVE_STRING_H)
check_include_file_cxx("pfring.h" HAVE_PFRING_H)
check_include_file_cxx("sys/sockio.h" HAVE_SYS_SOCKIO_H)
check_include_file_cxx("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file_cxx("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file_cxx("unistd.h" HAVE_UNISTD_H)
check_include_file_cxx("uuid/uuid.h" HAVE_UUID_UUID_H)
check_include_file_cxx("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file_cxx("libintl.h" HAVE_LIBINTL_H)
check_include_file_cxx("limits.h" HAVE_LIMITS_H)
check_include_file_cxx("netdb.h " HAVE_NETDB_H)
check_include_file_cxx("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file_cxx("stddef.h" HAVE_STDDEF_H)
check_include_file_cxx("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file_cxx("sys/time.h" HAVE_SYS_TIME_H)
check_include_file_cxx("syslog.h" HAVE_SYSLOG_H)
check_include_file_cxx("dnet.h" HAVE_DNET_H)
check_include_file_cxx("dumbnet.h" HAVE_DUMBNET_H)
check_include_file_cxx("pcre.h" HAVE_PCRE_H)
check_include_file_cxx("zlib.h" HAVE_ZLIB_H)



# checking for specific functions
check_function_exists(sigaction HAVE_SIGACTION)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(vswprintf HAVE_VSWPRINTF)
check_function_exists(wprintf HAVE_WPRINTF)
check_function_exists(memrchr HAVE_MEMRCHR)
check_function_exists(inet_ntop HAVE_INET_NTOP)
check_function_exists(snprintf HAVE_SNPRINTF)
check_function_exists(vsnprintf HAVE_VSNPRINTF)





#--------------------------------------------------------------------------
# Checks for typedefs, structures, and compiler characteristics.
#--------------------------------------------------------------------------
SET (CMAKE_EXTRA_INCLUDE_FILES "stdint.h")

check_type_size("char" SIZEOF_CHAR)
check_type_size(int8_t INT8_T)
check_type_size(int16_t INT16_T)
check_type_size(int32_t INT32_T)
check_type_size(int64_t INT64_T)
check_type_size(u_int8_t U_INT8_T)
check_type_size(u_int16_t U_INT16_T)
check_type_size(u_int32_t U_INT32_T)
check_type_size(u_int64_t U_INT64_T)
check_type_size(uint8_t UINT8_T)
check_type_size(uint16_t UINT16_T)
check_type_size(uint32_t UINT32_T)
check_type_size(uint64_t UINT64_T)
check_type_size("short" SIZEOF_SHORT)
check_type_size("int" SIZEOF_INT)
check_type_size("unsigned int" SIZEOF_UNSIGNED_INT)
check_type_size("long int" SIZEOF_LONG_INT)
check_type_size("unsigned long int" SIZEOF_UNSIGNED_LONG_INT)
check_type_size("long long int" SIZEOF_LONG_LONG_INT)
check_type_size("unsigned long long int" SIZEOF_UNSIGNED_LONG_LONG_INT)



# set all of the library variables


# DAQ specific functions
CHECK_LIBRARY_EXISTS(daq daq_hup_apply ${DAQ_LIBRARIES} HAVE_DAQ_HUP_APPLY)
CHECK_LIBRARY_EXISTS(daq daq_acquire_with_meta ${DAQ_LIBRARIES} HAVE_DAQ_ACQUIRE_WITH_META)


if ( OPENSSL_CRYPTO_LIBRARY )
    set (HAVE_LIBCRYPTO 1)
else()
    message(FATAL_ERROR "Could not find openssl -lcrypto")
endif()



include (TestBigEndian)
TEST_BIG_ENDIAN ( WORDS_BIGENDIAN )



# Set all of the library variables since we already found them
set(HAVE_LIBPCRE "YES")
set(HAVE_LIBZ "YES")
set(HAVE_LIBPCAP 1)
CHECK_LIBRARY_EXISTS(pcap pcap_lib_version "${PCAP_LIBRARIES}" HAVE_PCAP_LIB_VERSION)
CHECK_LIBRARY_EXISTS(pcap pcap_lex_destroy "${PCAP_LIBRARIES}" HAVE_PCAP_LEX_DESTROY)


if (HAVE_DNET_H)
    set (HAVE_LIBDNET "YES")
else (HAVE_DNET_H)
    set(HAVE_LIBDUMBNET "YES")
endif (HAVE_DNET_H)


find_library(MATH_LIBRARY m)
if(MATH_LIBRARY)
    SET (HAVE_LIBM 1)
endif(MATH_LIBRARY)


# Check and set CXX11 compiler options
include ( "${CMAKE_CURRENT_LIST_DIR}/CheckCXX11Features.cmake" )
if (HAS_CXX11_FUNC)
    SET(HAVE___FUNCTION__ 1)
endif(HAS_CXX11_FUNC)


#############################################################################
#############################################################################
################  Foo that still needs to be written   ######################
#############################################################################
#############################################################################


find_library(NSL nsl)
if (NSL)
    set(HAVE_LIBNSL "YES")
endif(NSL)


#/* Define to 1 if you have the `rt' library (-lrt). */
check_library_exists(rt nanosleep "" HAVE_LIBRT)
# cmakedefine HAVE_LIBRT

#/* Define to 1 if you have the `socket' library (-lsocket). */
# cmakedefine HAVE_LIBSOCKET

#/* Define to 1 if you have the `uuid' library (-luuid). */
# cmakedefine HAVE_LIBUUID
















#/* Define if broken SIOCGIFMTU */
#cmakedefine BROKEN_SIOCGIFMTU


#/* Define if errlist is predefined */
#cmakedefine ERRLIST_PREDEFINED

#/* DAQ version supports address space ID in header. */
#cmakedefine HAVE_DAQ_ADDRESS_SPACE_ID





#/* Define if the compiler supports visibility declarations. */
#cmakedefine HAVE_VISIBILITY


#/* Define whether yylex_destroy is supported in flex version */
#cmakedefine HAVE_YYLEX_DESTROY


#/* Define if HP-UX 10 or 11 */
#cmakedefine HPUX

#/* For INADDR_NONE definition */
#cmakedefine INADDR_NONE

#/* Define to the sub-directory in which libtool stores uninstalled libraries.
#   */
#undef LT_OBJDIR

#/* Name of package */
#undef PACKAGE

#/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

#/* Define to the full name of this package. */
#undef PACKAGE_NAME

#/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

#/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

#/* Define to the home page for this package. */
#undef PACKAGE_URL

#/* Define to the version of this package. */
#undef PACKAGE_VERSION


#/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS






###############################################################################
###############################################################################
#
#   Finally, create the config.h file


configure_file (
    "${PROJECT_SOURCE_DIR}/config.cmake.h.in"
    "${PROJECT_SOURCE_DIR}/config.h"
    )

add_definitions( -DHAVE_CONFIG_H )
#set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${PROJECT_SOURCE_DIR}/config.h")

