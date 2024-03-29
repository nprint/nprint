#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([nprint], [1.2.1], [jordanah@princeton.edu])
AC_CONFIG_SRCDIR([src/nprint.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_loop])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa])

# OS Check here
WRAPPER_LDFLAGS = ""
WRAPPER_CPPFLAGS = ""
AC_CANONICAL_HOST
AS_CASE([$host_os],
        [darwin*],
        [
         WRAPPER_CPPFLAGS="$WRAPPER_CPPFLAGS -I/usr/local/include"
         WRAPPER_LDFLAGS="$WRAPPER_LDFLAGS -largp -L/usr/local/lib"
        ])

AC_SUBST([WRAPPER_CPPFLAGS])
AC_SUBST([WRAPPER_LDFLAGS])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_FILES([Makefile])

#
AC_OUTPUT
