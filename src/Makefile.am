lib_LTLIBRARIES = libwhirlpool.la

libwhirlpool_la_SOURCES = Whirlpool.c

include_HEADERS = whirlpool.h

libwhirlpool_la_LDFLAGS= -version-info 0:1:0

bin_PROGRAMS = whirlpoolsum

dist_man_MANS = whirlpoolsum.1

whirlpoolsum_SOURCES = whirlpoolsum.c

whirlpoolsum_LDADD = -lwhirlpool
