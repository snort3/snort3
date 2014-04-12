#
#
#  Library containing all of the information regarding specific platforms, and their specific libraries.
# 

#FILE UNTESTED!!!

#AC_CANONICAL_HOST
#linux="no"
#sunos4="no"
#so_with_static_lib="yes"
#
#case "$host" in



if (${CMAKE_SYSTEM_NAME} EQUAL "openbsd")
    set(OPENBSD "YES")
#    so_with_static_lib="no"

    if(CMAKE_SYSTEM_VERSION VERSION_GREATER "2.3")
        set(BROKEN_SIOCGIFMTU "YES")
    endif(CMAKE_SYSTEM_VERSION VERSION_GREATER "2.3")


elseif (${CMAKE_SYSTEM_NAME} EQUAL "openbsd")


endif(${CMAKE_SYSTEM_NAME} EQUAL "openbsd")


if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set (LINUX 1)
endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")

if (${CMAKE_SYSTEM_NAME} MATCHES "Solaris")
    set (Solaris 1)
endif (${CMAKE_SYSTEM_NAME} MATCHES "Solaris")

if (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
    set (SUNOS 1)
endif (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")


  
#/* Define if building universal (internal helper macro) */
#cmakedefine AC_APPLE_UNIVERSAL_BUILD

#/* Define if AIX */
#cmakedefine AIX

#/* Define if BSDi */
#cmakedefine BSDI


#/* Define if MacOS */
#undef MACOS

#/* Define if OpenBSD < 2.3 */
#undef OPENBSD

#/* Define if Tru64 */
#undef OSF1



# System Checks

if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set (FREEBSD 1)
endif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")


#/* Define if Irix 6 */
#undef IRIX


#  *-sgi-irix5*)
#    AC_DEFINE([IRIX],[1],[Define if Irix 5])
#    no_libsocket="yes"
#    no_libnsl="yes"
#    if test -z "$GCC"; then
#      sgi_cc="yes"
#    fi
#    LDFLAGS="${LDFLAGS} -L/usr/local/lib"
#    extra_incl="-I/usr/local/include"
#    ;;
#  *-sgi-irix6*)
#    AC_DEFINE([IRIX],[1],[Define if Irix 6])
#    no_libsocket="yes"
#    no_libnsl="yes"
#    if test -z "$GCC"; then
#      sgi_cc="yes"
#    fi
#    LDFLAGS="${LDFLAGS} -L/usr/local/lib"
#    extra_incl="-I/usr/local/include"
#    ;;
#  *-solaris*)
#    AC_DEFINE([SOLARIS],[1],[Define if Solaris])
#    CONFIGFLAGS="${CONFIGFLAGS} -DBSD_COMP -D_REENTRANT"
#    rt_nanosleep="yes"
#    ;;
#  *-sunos*)
#    AC_DEFINE([SUNOS],[1],[Define if SunOS])
#   sunos4="yes"
#    ;;
#  *-linux*)
#    linux="yes"
#    AC_DEFINE([LINUX],[1],[Define if Linux])
#    AC_SUBST(extra_incl)
#    extra_incl="-I/usr/include/pcap"
#    ;;
#  *-hpux10*|*-hpux11*)
#    AC_DEFINE([HPUX],[1],[Define if HP-UX 10 or 11])
#    AC_DEFINE([WORDS_BIGENDIAN],[1],[Define if words are big endian])
#    AC_SUBST(extra_incl)
#    extra_incl="-I/usr/local/include"
#    ;;
#  *-freebsd*)
#    AC_DEFINE([FREEBSD],[1],[Define if FreeBSD])
#    ;;
#  *-bsdi*)
#    AC_DEFINE([BSDI],[1],[Define if BSDi])
#    ;;
#  *-aix*)
#    AC_DEFINE([AIX],[1],[Define if AIX])
#    ;;
#  *-osf4*)
#    AC_DEFINE([OSF1],[1],[Define if OSF-4])
#    CONFIGFLAGS="${CONFIGFLAGS} -DOSF1"
#    ;;
#  *-osf5.1*)
#    AC_DEFINE([OSF1],[1],[Define if OSF-5.1])
#    CONFIGFLAGS="${CONFIGFLAGS} -DOSF1"
#    ;;
#  *-tru64*)
#    AC_DEFINE([OSF1],[1],[Define if Tru64])
#    CONFIGFLAGS="${CONFIGFLAGS} -DOSF1"
#    ;;
# it is actually <platform>-apple-darwin1.2 or <platform>-apple-rhapsody5.x but lets stick with this for the moment
#  *-apple*)
#    AC_DEFINE([MACOS],[1],[Define if MacOS])
#    AC_DEFINE([BROKEN_SIOCGIFMTU],[1],[Define if broken SIOCGIFMTU])
#esac

