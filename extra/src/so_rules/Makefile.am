AUTOMAKE_OPTIONS=foreign

optlibdir = $(pkglibdir)/so_rules
optlib_LTLIBRARIES = lib18758.la
lib18758_la_CXXFLAGS = $(AM_CXXFLAGS)
lib18758_la_LDFLAGS = -export-dynamic -shared
lib18758_la_SOURCES = sid_18758.cc sid_18758.h

BUILT_SOURCES = \
sid_18758.h

%.gz : %.txt
	gzip --best --no-name --stdout $< > $@

%.h : %.gz
	xxd -i $< > $@

AM_CXXFLAGS = @AM_CXXFLAGS@

