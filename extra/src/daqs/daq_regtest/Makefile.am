daq_regtestlibdir = $(pkglibdir)/daqs

AM_CFLAGS   = @SNORT3_CFLAGS@ -std=gnu99

daq_regtestlib_LTLIBRARIES = daq_regtest.la
daq_regtest_la_CFLAGS   = $(AM_CFLAGS)
daq_regtest_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
daq_regtest_la_SOURCES  = daq_regtest.c
