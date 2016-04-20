daq_socketlibdir = $(pkglibdir)/daqs

AM_CFLAGS   = @SNORT3_CFLAGS@

daq_socketlib_LTLIBRARIES = libdaq_socket.la
libdaq_socket_la_CFLAGS   = $(AM_CFLAGS)
libdaq_socket_la_LDFLAGS  = -export-dynamic -shared
libdaq_socket_la_SOURCES  = daq_socket.c
