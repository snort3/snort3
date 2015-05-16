AUTOMAKE_OPTIONS=foreign

daqlibdir = $(pkglibdir)/daqs

daqlib_LTLIBRARIES = daq_socket.la
daq_socket_la_CFLAGS = -DBUILDING_SO
daq_socket_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_socket_la_SOURCES = daq_socket.c daq_socket.h

daqlib_LTLIBRARIES += daq_file.la
daq_file_la_CFLAGS = -DBUILDING_SO
daq_file_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_file_la_SOURCES = daq_file.c daq_socket.h

daqlib_LTLIBRARIES += daq_user.la
daq_user_la_CFLAGS = -DBUILDING_SO
daq_user_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_user_la_SOURCES = daq_user.c daq_socket.h

AM_CFLAGS = @AM_CFLAGS@

