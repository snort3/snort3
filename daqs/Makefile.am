
x_includedir = $(pkgincludedir)/daqs
x_include_HEADERS = daq_user.h

daqlibdir = $(pkglibdir)/daqs

daqlib_LTLIBRARIES = daq_file.la
daq_file_la_CFLAGS = $(AM_CFLAGS) -DBUILDING_SO
daq_file_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
daq_file_la_SOURCES = daq_file.c

daqlib_LTLIBRARIES += daq_hext.la
daq_hext_la_CFLAGS = $(AM_CFLAGS) -DBUILDING_SO
daq_hext_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
daq_hext_la_SOURCES = daq_hext.c

