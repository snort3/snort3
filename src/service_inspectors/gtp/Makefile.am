
file_list = \
gtp.cc \
gtp.h \
gtp_inspect.cc \
gtp_inspect.h \
gtp_module.cc \
gtp_module.h \
gtp_parser.cc \
gtp_parser.h \
ips_gtp_info.cc \
ips_gtp_type.cc \
ips_gtp_version.cc

if STATIC_INSPECTORS
noinst_LIBRARIES = libgtp_inspect.a
libgtp_inspect_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libgtp_inspect.la
libgtp_inspect_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libgtp_inspect_la_LDFLAGS = -export-dynamic -shared
libgtp_inspect_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

