
optlibdir = $(pkglibdir)/so_rules
optlib_LTLIBRARIES = lib18758.la
lib18758_la_CXXFLAGS = $(AM_CXXFLAGS)
lib18758_la_LDFLAGS = -export-dynamic -shared
lib18758_la_SOURCES = sid_18758.cc sid_18758.h

# to make plain text rule header:
%.h : %.txt
	snort --rule-to-text < $< > $@

# to make compressed rule header:
%.h : %.pro
	snort --rule-to-hex < $< > $@

AM_CXXFLAGS = @AM_CXXFLAGS@

