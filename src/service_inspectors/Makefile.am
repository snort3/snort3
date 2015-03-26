## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libservice_inspectors.a

libservice_inspectors_a_SOURCES = \
service_inspectors.cc \
service_inspectors.h

# FIXIT LIBADD here causes undefineds
#libservice_inspectors_a_LIBADD = \
#back_orifice/libback_orifice.a \
#ftp_telnet/libftp_telnet.a \
#http_inspect/libhttp_inspect.a \
#nhttp_inspect/libnhttp_inspect.a \
#rpc_decode/librpc_decode.a
#wizard/libwizard.a

SUBDIRS = \
back_orifice \
ftp_telnet \
http_inspect \
nhttp_inspect \
rpc_decode \
ssh \
wizard

AM_CXXFLAGS = @AM_CXXFLAGS@

