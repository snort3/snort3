daq_socketlibdir = $(pkglibdir)/daqs

AM_CFLAGS   = @SNORT3_CFLAGS@ -std=gnu99

daq_socketlib_LTLIBRARIES = daq_socket.la
daq_socket_la_CFLAGS   = $(AM_CFLAGS)
daq_socket_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
daq_socket_la_SOURCES  = daq_socket.c
