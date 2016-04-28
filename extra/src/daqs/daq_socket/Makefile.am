daq_socketlibdir = $(pkglibdir)/daqs

AM_CFLAGS   = @SNORT3_CFLAGS@ -std=gnu99

daq_socketlib_LTLIBRARIES = libdaq_socket.la
libdaq_socket_la_CFLAGS   = $(AM_CFLAGS)
libdaq_socket_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libdaq_socket_la_LDFLAGS += -module
libdaq_socket_la_SOURCES  = daq_socket.c
