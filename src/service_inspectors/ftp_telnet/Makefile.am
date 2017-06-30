
file_list = \
ft_main.cc ft_main.h \
ftp.cc \
ftp_module.cc ftp_module.h \
ftp_parse.cc ftp_parse.h \
ftp_print.cc ftp_print.h \
ftp_data.cc ftp_data.h \
ftp_bounce_lookup.cc ftp_bounce_lookup.h \
ftp_client.h \
ftp_cmd_lookup.cc ftp_cmd_lookup.h \
ftpp_return_codes.h \
ftpp_si.cc ftpp_si.h \
ftpp_ui_config.cc ftpp_ui_config.h \
ftp_server.h \
ftp_splitter.cc ftp_splitter.h \
ftpdata_splitter.cc ftpdata_splitter.h \
pp_ftp.cc pp_ftp.h \
pp_telnet.cc pp_telnet.h \
telnet.cc telnet.h \
telnet_module.cc telnet_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libftp_telnet.a
libftp_telnet_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = ftp_telnet.la
ftp_telnet_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
ftp_telnet_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
ftp_telnet_la_SOURCES = $(file_list)
endif

