AUTOMAKE_OPTIONS=foreign no-dependencies

file_list = \
ftp_module.cc ftp_module.h \
telnet_module.cc telnet_module.h \
ftp_parse.cc ftp_parse.h \
ftp_print.cc ftp_print.h \
ftp.cc \
ftp_bounce_lookup.cc ftp_bounce_lookup.h \
ftp_client.h \
ftp_cmd_lookup.cc ftp_cmd_lookup.h \
ftpp_include.h \
ftpp_return_codes.h \
ftpp_si.cc ftpp_si.h \
ftpp_ui_config.cc ftpp_ui_config.h \
ftp_server.h \
hi_util_kmap.cc hi_util_kmap.h \
hi_util_xmalloc.cc hi_util_xmalloc.h \
pp_ftp.cc pp_ftp.h \
pp_telnet.cc pp_telnet.h \
ft_main.cc ft_main.h \
ftpp_util_kmap.h \
telnet.cc

if STATIC_INSPECTORS
noinst_LIBRARIES = libftp_telnet.a
libftp_telnet_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libftp_telnet.la
libftp_telnet_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libftp_telnet_la_LDFLAGS = -export-dynamic -shared
libftp_telnet_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

