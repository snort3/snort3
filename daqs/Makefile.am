
daqlibdir = $(pkglibdir)/daqs

daqlib_LTLIBRARIES = daq_socket.la
daq_socket_la_CFLAGS = -DBUILDING_SO
daq_socket_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_socket_la_SOURCES = daq_socket.c daq_socket.h

daqlib_LTLIBRARIES += daq_file.la
daq_file_la_CFLAGS = -DBUILDING_SO
daq_file_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_file_la_SOURCES = daq_file.c daq_socket.h

daqlib_LTLIBRARIES += daq_hext.la
daq_hext_la_CFLAGS = -DBUILDING_SO
daq_hext_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_hext_la_SOURCES = daq_hext.c daq_socket.h

