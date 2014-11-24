AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS = u2boat

u2boat_SOURCES = u2boat.cc u2boat.h
u2boat_CFLAGS = @CFLAGS@ $(AM_CFLAGS)
u2boat_LDADD = -lpcap

AM_CXXFLAGS = @AM_CXXFLAGS@

dist_doc_DATA = README.u2boat

