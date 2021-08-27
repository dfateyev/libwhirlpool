lib_LTLIBRARIES = libwhirlpool.la

libwhirlpool_la_SOURCES = Whirlpool.c

include_HEADERS = whirlpool.h

libwhirlpool_la_LDFLAGS= -no-undefined -version-info 0:2:0

bin_PROGRAMS = whirlpoolsum

dist_man_MANS = whirlpoolsum.1

whirlpoolsum_SOURCES = whirlpoolsum.c

whirlpoolsum_LDADD = libwhirlpool.la
