# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libwhirlpool], [1.1], [denis@fateyev.com])
AC_CONFIG_SRCDIR([src/Whirlpool.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([limits.h getopt.h stdlib.h errno.h string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset strcasecmp strerror])

AM_INIT_AUTOMAKE
LT_INIT

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
